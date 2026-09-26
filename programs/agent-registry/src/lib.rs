// ============================================================================
// Agent Registry — Solana Program
// ============================================================================
//
// PURPOSE:
//   Stores the on-chain proof that an AI agent (bot) exists, is tied to a
//   responsible party, and records when it was registered or revoked.
//
// WHY ON-CHAIN:
//   Regent's database could be altered by an admin. The on-chain record
//   cannot be altered by anyone — not even Regent. This gives regulators
//   and auditors an independent source of truth.
//
// OPERATIONS:
//   1. initialize   — one-time setup: sets who the authority (operator) is
//   2. register_agent — creates an Agent account for a given agent_id
//   3. revoke_agent   — marks an agent as revoked (irreversible)
//
// STORAGE MODEL (Solana-specific):
//   Unlike Ethereum where a contract has one big mapping, Solana stores
//   each agent as a SEPARATE on-chain account. The account's address is
//   derived deterministically from the agent_id using a PDA (Program
//   Derived Address). This means:
//     - Given an agent_id, anyone can compute the account address
//     - No enumeration is needed to find an agent
//     - Each account pays rent (deposit, refundable if closed)
//     - Accounts can be read in parallel (Solana's key advantage)
//
// ACCESS CONTROL:
//   Only the designated "authority" (operator wallet) can register or revoke.
//   The authority is set during initialization and can be transferred by the
//   current authority. This is similar to OpenZeppelin's Ownable pattern.
//
// SIZE: ~180 lines including comments. The actual logic is ~60 lines.
// ============================================================================

use anchor_lang::prelude::*;

// This is a PLACEHOLDER program ID. When you run `anchor build` for the first
// time, Anchor generates a real keypair in target/deploy/agent_registry-keypair.json
// and prints the program ID. Replace this value with the real one.
declare_id!("5jBmqyeo1vUAjHbEFuY59NMGTQR8cEe9Jvz2uCwCjp3L");

// ============================================================================
// PROGRAM MODULE — contains all instructions (functions) the program exposes
// ============================================================================
#[program]
pub mod agent_registry {
    use super::*;

    // ------------------------------------------------------------------------
    // initialize — one-time setup
    // ------------------------------------------------------------------------
    // Called once after deployment to set the operator authority.
    // The authority is the wallet that can register and revoke agents.
    //
    // WHY SEPARATE FROM DEPLOY:
    //   Solana programs don't have constructors like Solidity. The program
    //   is deployed as bytecode with no state. We need a separate instruction
    //   to create the "config" account that stores who the authority is.
    //
    // PARAMS:
    //   ctx — contains the accounts this instruction needs (see InitializeConfig)
    // ------------------------------------------------------------------------
    pub fn initialize(ctx: Context<InitializeConfig>) -> Result<()> {
        let config = &mut ctx.accounts.config;

        // The person who calls initialize becomes the authority.
        // This should be the deployer wallet (admin).
        config.authority = ctx.accounts.authority.key();

        // Track total agents for analytics (not required for core logic)
        config.total_agents = 0;

        msg!("AgentRegistry initialized. Authority: {}", config.authority);
        Ok(())
    }

    // ------------------------------------------------------------------------
    // register_agent — create an on-chain agent record
    // ------------------------------------------------------------------------
    // Creates a new Agent PDA account with the given agent_id.
    //
    // WHAT HAPPENS:
    //   1. Solana runtime creates a new account (paid by authority)
    //   2. The account address is derived from: seeds = ["agent", agent_id]
    //   3. We store agent_id, responsible_party, timestamp, revoked=false
    //   4. We emit an AgentRegistered event
    //   5. We increment the global agent counter
    //
    // SECURITY:
    //   - Only the authority can call this (enforced by `has_one` constraint)
    //   - The same agent_id cannot be registered twice (PDA is deterministic —
    //     trying to init the same seeds fails with "already in use")
    //   - responsible_party is a Pubkey — it identifies WHO is accountable
    //
    // COST:
    //   ~0.001 SOL tx fee + ~0.002 SOL rent deposit (refundable)
    //
    // PARAMS:
    //   agent_id           — 32-byte unique identifier for the agent
    //   did_hash           — SHA-256 hash of the W3C DID string
    //   responsible_party  — Pubkey of the human/company responsible
    // ------------------------------------------------------------------------
    pub fn register_agent(
        ctx: Context<RegisterAgent>,
        agent_id: [u8; 32],
        did_hash: [u8; 32],
        responsible_party: Pubkey,
    ) -> Result<()> {
        let agent = &mut ctx.accounts.agent;
        let clock = Clock::get()?;

        // Store agent data in the PDA account
        agent.agent_id = agent_id;
        agent.did_hash = did_hash;
        agent.responsible_party = responsible_party;
        agent.registered_at = clock.unix_timestamp;
        agent.revoked = false;
        agent.bump = ctx.bumps.agent;

        // Increment global counter
        let config = &mut ctx.accounts.config;
        config.total_agents = config.total_agents.checked_add(1).unwrap();

        // Emit event with did_hash
        emit!(AgentRegistered {
            agent_id,
            did_hash,
            responsible_party,
            timestamp: clock.unix_timestamp,
        });

        msg!(
            "Agent registered: {:?}, responsible: {}",
            agent_id,
            responsible_party
        );
        Ok(())
    }

    // ------------------------------------------------------------------------
    // revoke_agent — permanently mark an agent as revoked
    // ------------------------------------------------------------------------
    // Sets revoked=true on an existing Agent account. This is IRREVERSIBLE.
    //
    // WHY IRREVERSIBLE:
    //   If a bot goes rogue or an employee leaves, the agent must be killed
    //   permanently. Allowing un-revocation would undermine the trust model.
    //   There is intentionally no `unrevoke_agent` function — it physically
    //   cannot be called because it doesn't exist in the compiled program.
    //
    // WHAT HAPPENS DOWNSTREAM:
    //   1. blockchain-worker publishes "onchain.agent_revoked" event
    //   2. api-identity sets agent status to "revoked" in PostgreSQL
    //   3. All mandates for this agent are automatically invalidated
    //   4. Future authorize() calls for this agent's mandates will fail
    //
    // SECURITY:
    //   - Only the authority can revoke
    //   - Cannot revoke an already-revoked agent (prevents double events)
    //
    // COST: ~0.001 SOL tx fee (no new account created)
    // ------------------------------------------------------------------------
    pub fn revoke_agent(ctx: Context<RevokeAgent>, _agent_id: [u8; 32]) -> Result<()> {
        let agent = &mut ctx.accounts.agent;

        // Guard: prevent revoking an already-revoked agent
        require!(!agent.revoked, AgentError::AlreadyRevoked);

        let clock = Clock::get()?;
        agent.revoked = true;
        agent.revoked_at = Some(clock.unix_timestamp);

        emit!(AgentRevoked {
            agent_id: agent.agent_id,
            timestamp: clock.unix_timestamp,
        });

        msg!("Agent revoked: {:?}", agent.agent_id);
        Ok(())
    }

    // ------------------------------------------------------------------------
    // transfer_authority — change who can register/revoke agents
    // ------------------------------------------------------------------------
    // Transfers the operator authority to a new wallet.
    //
    // USE CASE:
    //   - Rotating the operator key (security best practice)
    //   - Transferring operations to a new team member
    //   - Moving from a hot wallet to a multisig
    //
    // SECURITY:
    //   - Only the current authority can transfer
    //   - Cannot transfer to the zero address (Pubkey::default)
    // ------------------------------------------------------------------------
    pub fn transfer_authority(
        ctx: Context<TransferAuthority>,
        new_authority: Pubkey,
    ) -> Result<()> {
        // Guard: don't allow transferring to the default (zero) pubkey
        require!(
            new_authority != Pubkey::default(),
            AgentError::InvalidAuthority
        );

        let config = &mut ctx.accounts.config;
        let old = config.authority;
        config.authority = new_authority;

        msg!("Authority transferred: {} -> {}", old, new_authority);
        Ok(())
    }

    // ------------------------------------------------------------------------
    // register_user — create an on-chain record for a KYC-verified user
    // ------------------------------------------------------------------------
    // Stores the user's DID hash and KYC attestation hash on-chain.
    // This proves: a human was verified, and their DID is real.
    //
    // Called after KYC verification completes in api-platform.
    //
    // PARAMS:
    //   user_id_hash       — SHA-256 of the user's UUID
    //   did_hash           — SHA-256 of the user's DID string
    //   kyc_attestation    — SHA-256 of the full KYC result (no PII)
    //   kyc_country        — 2-byte country code (e.g., b"KZ")
    // ------------------------------------------------------------------------
    pub fn register_user(
        ctx: Context<RegisterUser>,
        user_id_hash: [u8; 32],
        did_hash: [u8; 32],
        kyc_attestation: [u8; 32],
        kyc_country: [u8; 2],
    ) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        let clock = Clock::get()?;

        user.user_id_hash = user_id_hash;
        user.did_hash = did_hash;
        user.kyc_attestation_hash = kyc_attestation;
        user.kyc_country = kyc_country;
        user.kyc_verified = true;
        user.registered_at = clock.unix_timestamp;
        user.bump = ctx.bumps.user_account;

        let config = &mut ctx.accounts.config;
        config.total_agents = config.total_agents.checked_add(0).unwrap(); // no change to counter

        emit!(UserRegistered {
            user_id_hash,
            did_hash,
            kyc_attestation,
            kyc_country,
            timestamp: clock.unix_timestamp,
        });

        msg!("User registered on-chain with KYC attestation");
        Ok(())
    }
}

// ============================================================================
// ACCOUNT STRUCTS — define what data is stored on-chain
// ============================================================================

// ---------------------------------------------------------------------------
// RegistryConfig — global config account (one per program deployment)
// ---------------------------------------------------------------------------
// Stores the authority (operator) pubkey and global counters.
// Created once during `initialize`.
//
// DISCRIMINATOR: Anchor adds an 8-byte discriminator at the start of every
// account. This prevents accidentally deserializing the wrong account type.
// That's why space calculations always start with 8 +.
// ---------------------------------------------------------------------------
#[account]
#[derive(InitSpace)]
pub struct RegistryConfig {
    /// The wallet authorized to register and revoke agents.
    pub authority: Pubkey,          // 32 bytes
    /// Total number of agents ever registered (not decremented on revoke).
    pub total_agents: u64,          // 8 bytes
}
// Total: 8 (discriminator) + 32 + 8 = 48 bytes

// ---------------------------------------------------------------------------
// Agent — per-agent account (one per registered agent)
// ---------------------------------------------------------------------------
// Created by `register_agent`. The account address is a PDA derived from
// seeds = ["agent", agent_id]. Anyone who knows the agent_id can compute
// the address and read the data — no enumeration needed.
// ---------------------------------------------------------------------------
#[account]
#[derive(InitSpace)]
pub struct Agent {
    /// Unique identifier for this agent (matches the off-chain AgentID).
    pub agent_id: [u8; 32],             // 32 bytes
    /// SHA-256 hash of the W3C DID string (did:regent:{chain}:{agent_id}).
    /// Enables on-chain DID verification without storing the full DID string.
    pub did_hash: [u8; 32],             // 32 bytes
    /// The human/company responsible for this agent's actions.
    pub responsible_party: Pubkey,       // 32 bytes
    /// Unix timestamp when this agent was registered.
    pub registered_at: i64,              // 8 bytes
    /// Whether this agent has been permanently revoked.
    pub revoked: bool,                   // 1 byte
    /// Unix timestamp when revoked (None if still active).
    pub revoked_at: Option<i64>,         // 1 + 8 = 9 bytes (Option adds 1 byte tag)
    /// PDA bump seed — stored for efficient address re-derivation.
    pub bump: u8,                        // 1 byte
}
// Total: 8 (discriminator) + 32 + 32 + 32 + 8 + 1 + 9 + 1 = 123 bytes

// ---------------------------------------------------------------------------
// User — per-user account for KYC-verified humans
// ---------------------------------------------------------------------------
#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    /// SHA-256 of the user's UUID.
    pub user_id_hash: [u8; 32],         // 32 bytes
    /// SHA-256 of the user's DID string.
    pub did_hash: [u8; 32],             // 32 bytes
    /// SHA-256 of the full KYC result (no PII — just the hash).
    pub kyc_attestation_hash: [u8; 32], // 32 bytes
    /// 2-byte country code (e.g., b"KZ").
    pub kyc_country: [u8; 2],           // 2 bytes
    /// Whether KYC is verified.
    pub kyc_verified: bool,             // 1 byte
    /// Unix timestamp of registration.
    pub registered_at: i64,             // 8 bytes
    /// PDA bump.
    pub bump: u8,                       // 1 byte
}
// Total: 8 (discriminator) + 32 + 32 + 32 + 2 + 1 + 8 + 1 = 116 bytes

// ============================================================================
// INSTRUCTION ACCOUNT CONTEXTS — define which accounts each instruction needs
// ============================================================================
// Anchor validates these BEFORE your function code runs:
//   - Are the right accounts provided?
//   - Are they the right type?
//   - Are the required signatures present?
//   - Do the constraints (has_one, seeds, etc.) hold?
// If any validation fails, the transaction is rejected without executing.
// ============================================================================

// ---------------------------------------------------------------------------
// InitializeConfig — accounts needed by `initialize`
// ---------------------------------------------------------------------------
#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    // Create the global config account.
    // `init` = create new account (fails if it already exists)
    // `payer` = who pays the rent deposit (the authority)
    // `space` = exact bytes needed (Anchor calculates via InitSpace)
    // `seeds` = PDA derivation: hash("config") → deterministic address
    #[account(
        init,
        payer = authority,
        space = 8 + RegistryConfig::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, RegistryConfig>,

    // The wallet that signs this transaction becomes the authority.
    // `mut` = this account's lamports will decrease (paying rent)
    // `Signer` = Anchor verifies this account actually signed the tx
    #[account(mut)]
    pub authority: Signer<'info>,

    // Solana system program — required for creating new accounts.
    // Every `init` instruction needs this.
    pub system_program: Program<'info, System>,
}

// ---------------------------------------------------------------------------
// RegisterAgent — accounts needed by `register_agent`
// ---------------------------------------------------------------------------
#[derive(Accounts)]
#[instruction(agent_id: [u8; 32])]
// ^ This tells Anchor to pass the `agent_id` instruction argument into
//   the account validation context, so we can use it in `seeds`.
pub struct RegisterAgent<'info> {
    // The global config — we read the authority and increment total_agents.
    // `has_one = authority` means: config.authority must equal authority.key()
    // This is how we enforce "only the operator can register".
    #[account(
        mut,
        seeds = [b"config"],
        bump,
        has_one = authority
    )]
    pub config: Account<'info, RegistryConfig>,

    // Create a new Agent PDA account.
    // `seeds = ["agent", agent_id]` makes the address deterministic:
    //   given an agent_id, anyone can compute this account's address.
    //
    // If someone tries to register the same agent_id twice, `init` will
    // fail because the PDA account already exists. This is automatic —
    // we don't need to write a "check if exists" guard.
    #[account(
        init,
        payer = authority,
        space = 8 + Agent::INIT_SPACE,
        seeds = [b"agent", agent_id.as_ref()],
        bump
    )]
    pub agent: Account<'info, Agent>,

    // The operator wallet — must be the authority from config.
    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ---------------------------------------------------------------------------
// RevokeAgent — accounts needed by `revoke_agent`
// ---------------------------------------------------------------------------
#[derive(Accounts)]
#[instruction(agent_id: [u8; 32])]
pub struct RevokeAgent<'info> {
    // Config — for authority check only (not mutated here)
    #[account(
        seeds = [b"config"],
        bump,
        has_one = authority
    )]
    pub config: Account<'info, RegistryConfig>,

    // The existing Agent account to revoke.
    // `mut` because we're changing its data (revoked = true).
    // `seeds` re-derive the PDA to ensure we're modifying the right account.
    #[account(
        mut,
        seeds = [b"agent", agent_id.as_ref()],
        bump = agent.bump
    )]
    pub agent: Account<'info, Agent>,

    // The operator — must match config.authority
    pub authority: Signer<'info>,
}

// ---------------------------------------------------------------------------
// TransferAuthority — accounts needed by `transfer_authority`
// ---------------------------------------------------------------------------
#[derive(Accounts)]
pub struct TransferAuthority<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump,
        has_one = authority
    )]
    pub config: Account<'info, RegistryConfig>,

    pub authority: Signer<'info>,
}

// ---------------------------------------------------------------------------
// RegisterUser — accounts needed by `register_user`
// ---------------------------------------------------------------------------
#[derive(Accounts)]
#[instruction(user_id_hash: [u8; 32])]
pub struct RegisterUser<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump,
        has_one = authority
    )]
    pub config: Account<'info, RegistryConfig>,

    #[account(
        init,
        payer = authority,
        space = 8 + UserAccount::INIT_SPACE,
        seeds = [b"user", user_id_hash.as_ref()],
        bump
    )]
    pub user_account: Account<'info, UserAccount>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// EVENTS — emitted to transaction logs, readable by off-chain listeners
// ============================================================================
// Events are NOT stored in account data. They're written to the transaction
// log and can be queried by off-chain services (blockchain-worker).
// They cost almost nothing to emit.
// ============================================================================

#[event]
pub struct AgentRegistered {
    pub agent_id: [u8; 32],
    pub did_hash: [u8; 32],
    pub responsible_party: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct AgentRevoked {
    pub agent_id: [u8; 32],
    pub timestamp: i64,
}

#[event]
pub struct UserRegistered {
    pub user_id_hash: [u8; 32],
    pub did_hash: [u8; 32],
    pub kyc_attestation: [u8; 32],
    pub kyc_country: [u8; 2],
    pub timestamp: i64,
}

// ============================================================================
// ERRORS — custom error codes returned on failure
// ============================================================================
// Each error has a unique code. When a transaction fails, the error code
// tells the caller exactly what went wrong — no guessing.
// ============================================================================

#[error_code]
pub enum AgentError {
    /// Attempted to revoke an agent that is already revoked.
    /// This prevents emitting duplicate revocation events.
    #[msg("Agent is already revoked")]
    AlreadyRevoked,

    /// Attempted to transfer authority to the zero/default pubkey.
    /// This would permanently lock out all operations.
    #[msg("New authority cannot be the default (zero) public key")]
    InvalidAuthority,
}
