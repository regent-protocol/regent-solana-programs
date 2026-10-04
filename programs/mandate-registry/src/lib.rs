// ============================================================================
// Mandate Registry — Solana Program
// ============================================================================
//
// PURPOSE:
//   Stores the on-chain proof that a spending mandate exists and is linked
//   to a specific agent. The mandate represents "this bot is authorized to
//   spend money under these conditions."
//
// WHAT'S ON-CHAIN vs OFF-CHAIN:
//   ON-CHAIN (this program):
//     - Mandate exists (proof)
//     - Which agent it belongs to (linkage)
//     - When it was registered (timestamp)
//     - Whether it's been revoked (status)
//
//   OFF-CHAIN (PostgreSQL + Redis):
//     - Actual spending limits (per-tx, daily, monthly)
//     - Currency
//     - Expiry date
//     - Running totals of spending
//
//   WHY NOT PUT LIMITS ON-CHAIN?
//     Limits change frequently (customer upgrades plan, admin adjusts).
//     Updating on-chain data costs gas and takes seconds. Redis counters
//     update in 2ms. The on-chain record proves "a mandate existed" —
//     the off-chain database enforces "what the limits are."
//
// STRUCTURE: Almost identical to AgentRegistry — same PDA pattern,
//   same authority model, same revocation logic.
//
// SIZE: ~140 lines including comments.
// ============================================================================

use anchor_lang::prelude::*;

declare_id!("8HAzw3UFGmabsHJkAsuGLfBZG8djYQ3J1FRNUVjkseMr");

#[program]
pub mod mandate_registry {
    use super::*;

    // ------------------------------------------------------------------------
    // initialize — one-time setup
    // ------------------------------------------------------------------------
    pub fn initialize(ctx: Context<InitializeMandateConfig>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.total_mandates = 0;

        msg!("MandateRegistry initialized. Authority: {}", config.authority);
        Ok(())
    }

    // ------------------------------------------------------------------------
    // register_mandate — create an on-chain mandate record
    // ------------------------------------------------------------------------
    // Creates a new Mandate PDA linked to an agent_id.
    //
    // WHY BOTH mandate_id AND agent_id:
    //   One agent can have MULTIPLE mandates (e.g., one for card payments,
    //   one for OTC trading, each with different limits). The mandate_id
    //   is unique; the agent_id connects it to the responsible agent.
    //
    // PARAMS:
    //   mandate_id — unique identifier (from PostgreSQL UUID)
    //   agent_id   — which agent this mandate belongs to
    // ------------------------------------------------------------------------
    pub fn register_mandate(
        ctx: Context<RegisterMandate>,
        mandate_id: [u8; 32],
        agent_id: [u8; 32],
    ) -> Result<()> {
        let mandate = &mut ctx.accounts.mandate;
        let clock = Clock::get()?;

        mandate.mandate_id = mandate_id;
        mandate.agent_id = agent_id;
        mandate.registered_at = clock.unix_timestamp;
        mandate.revoked = false;
        mandate.bump = ctx.bumps.mandate;

        let config = &mut ctx.accounts.config;
        config.total_mandates = config.total_mandates.checked_add(1).unwrap();

        emit!(MandateRegistered {
            mandate_id,
            agent_id,
            timestamp: clock.unix_timestamp,
        });

        msg!(
            "Mandate registered: {:?} for agent {:?}",
            &mandate_id[..8],
            &agent_id[..8]
        );
        Ok(())
    }

    // ------------------------------------------------------------------------
    // revoke_mandate — permanently mark a mandate as revoked
    // ------------------------------------------------------------------------
    // IRREVERSIBLE. Once revoked:
    //   - Off-chain authorize() calls will check on-chain status and reject
    //   - The agent can still exist (only the mandate is revoked)
    //   - A new mandate can be created for the same agent if needed
    //
    // USE CASES:
    //   - Customer cancels their card
    //   - Spending limits need to change (revoke old, create new)
    //   - Agent is compromised (revoke all its mandates)
    //   - Mandate expiry (off-chain expiry + on-chain revocation for finality)
    // ------------------------------------------------------------------------
    pub fn revoke_mandate(
        ctx: Context<RevokeMandate>,
        _mandate_id: [u8; 32],
    ) -> Result<()> {
        let mandate = &mut ctx.accounts.mandate;

        require!(!mandate.revoked, MandateError::AlreadyRevoked);

        let clock = Clock::get()?;
        mandate.revoked = true;
        mandate.revoked_at = Some(clock.unix_timestamp);

        emit!(MandateRevoked {
            mandate_id: mandate.mandate_id,
            agent_id: mandate.agent_id,
            timestamp: clock.unix_timestamp,
        });

        msg!("Mandate revoked: {:?}", &mandate.mandate_id[..8]);
        Ok(())
    }

    // ------------------------------------------------------------------------
    // transfer_authority - rotate the operator key without redeploying
    // ------------------------------------------------------------------------
    // Moves the operator authority stored in the config PDA to a new wallet.
    // Mirrors `transfer_authority` in agent-registry, which has had it since the
    // first release. These two programs did not, so the only way to rotate a
    // compromised operator key was to redeploy under new program ids, breaking
    // every existing on-chain reference.
    //
    // SECURITY:
    //   - Only the current authority can transfer (has_one on the context)
    //   - Cannot transfer to the zero address
    //   - The BPF upgrade authority is a separate key and is unaffected
    // ------------------------------------------------------------------------
    pub fn transfer_authority(
        ctx: Context<TransferAuthority>,
        new_authority: Pubkey,
    ) -> Result<()> {
        require!(
            new_authority != Pubkey::default(),
            MandateError::InvalidAuthority
        );

        let config = &mut ctx.accounts.config;
        let old = config.authority;
        config.authority = new_authority;

        msg!("Authority transferred: {} -> {}", old, new_authority);
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Admin / operator split (ADR-017, 2026-10)
    // ------------------------------------------------------------------------
    // `config.authority` is the OPERATOR: the hot key blockchain-worker signs every
    // write with. `AdminConfig.admin` is the ADMIN: a multisig (Squads) on mainnet,
    // the offline upgrade key on devnet. Only the admin may rotate the operator or
    // hand over admin. A compromised operator key can therefore write records but
    // can neither lock the protocol out nor change who is in charge.
    //
    // Migration-friendly: the admin lives in its own PDA ([b"admin"]) so existing
    // config accounts keep their layout. `init_admin` is the one-time bootstrap,
    // signed by the current operator; from then on `transfer_authority` is
    // admin-gated.
    // ------------------------------------------------------------------------
    pub fn init_admin(ctx: Context<InitAdmin>, admin: Pubkey) -> Result<()> {
        require!(admin != Pubkey::default(), MandateError::InvalidAuthority);
        let admin_config = &mut ctx.accounts.admin_config;
        admin_config.admin = admin;
        admin_config.bump = ctx.bumps.admin_config;
        msg!("Admin initialized: {}", admin);
        Ok(())
    }

    pub fn transfer_admin(ctx: Context<TransferAdmin>, new_admin: Pubkey) -> Result<()> {
        require!(new_admin != Pubkey::default(), MandateError::InvalidAuthority);
        let admin_config = &mut ctx.accounts.admin_config;
        let old = admin_config.admin;
        admin_config.admin = new_admin;
        msg!("Admin transferred: {} -> {}", old, new_admin);
        Ok(())
    }
}

// ============================================================================
// ACCOUNT STRUCTS
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct MandateConfig {
    pub authority: Pubkey,          // 32 bytes
    pub total_mandates: u64,        // 8 bytes
}
// Total: 8 + 32 + 8 = 48 bytes

#[account]
#[derive(InitSpace)]
pub struct Mandate {
    /// Unique identifier for this mandate.
    pub mandate_id: [u8; 32],       // 32 bytes
    /// Which agent this mandate authorizes to spend: the same 32-byte reference
    /// the agent registry uses as the agent's PDA seed (sha256 of the agent id).
    ///
    /// The mandate's TERMS are deliberately not here. Their salted commitment
    /// (`mandate_hash`) rides in every allow token, completion receipt and audit
    /// event, and the audit chain proves that trail is complete and ordered — so a
    /// commitment in this account would be redundant, and adding one would change
    /// the layout of accounts already written.
    pub agent_id: [u8; 32],         // 32 bytes
    /// Unix timestamp of registration.
    pub registered_at: i64,         // 8 bytes
    /// Whether this mandate has been permanently revoked.
    pub revoked: bool,              // 1 byte
    /// Unix timestamp of revocation (None if still active).
    pub revoked_at: Option<i64>,    // 9 bytes
    /// PDA bump seed.
    pub bump: u8,                   // 1 byte
}
// Total: 8 + 32 + 32 + 8 + 1 + 9 + 1 = 91 bytes

// ============================================================================
// INSTRUCTION ACCOUNT CONTEXTS
// ============================================================================

#[derive(Accounts)]
pub struct InitializeMandateConfig<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + MandateConfig::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, MandateConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(mandate_id: [u8; 32])]
pub struct RegisterMandate<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump,
        has_one = authority
    )]
    pub config: Account<'info, MandateConfig>,

    #[account(
        init,
        payer = authority,
        space = 8 + Mandate::INIT_SPACE,
        seeds = [b"mandate", mandate_id.as_ref()],
        bump
    )]
    pub mandate: Account<'info, Mandate>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(mandate_id: [u8; 32])]
pub struct RevokeMandate<'info> {
    #[account(
        seeds = [b"config"],
        bump,
        has_one = authority
    )]
    pub config: Account<'info, MandateConfig>,

    #[account(
        mut,
        seeds = [b"mandate", mandate_id.as_ref()],
        bump = mandate.bump
    )]
    pub mandate: Account<'info, Mandate>,

    pub authority: Signer<'info>,
}

// ============================================================================
// EVENTS
// ============================================================================


// ---------------------------------------------------------------------------
// AdminConfig — who may rotate the operator (ADR-017)
// ---------------------------------------------------------------------------
#[account]
#[derive(InitSpace)]
pub struct AdminConfig {
    /// The admin key: a multisig on mainnet, the offline upgrade key on devnet.
    pub admin: Pubkey,              // 32 bytes
    /// PDA bump seed.
    pub bump: u8,                   // 1 byte
}
// Total: 8 + 32 + 1 = 41 bytes

#[derive(Accounts)]
pub struct InitAdmin<'info> {
    #[account(
        seeds = [b"config"],
        bump,
        has_one = authority
    )]
    pub config: Account<'info, MandateConfig>,

    #[account(
        init,
        payer = authority,
        space = 8 + AdminConfig::INIT_SPACE,
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// The current operator bootstraps the admin exactly once (init fails after).
    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferAdmin<'info> {
    #[account(
        mut,
        seeds = [b"admin"],
        bump = admin_config.bump,
        has_one = admin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub admin: Signer<'info>,
}

#[event]
pub struct MandateRegistered {
    pub mandate_id: [u8; 32],
    pub agent_id: [u8; 32],
    pub timestamp: i64,
}

#[event]
pub struct MandateRevoked {
    pub mandate_id: [u8; 32],
    pub agent_id: [u8; 32],
    pub timestamp: i64,
}

// ============================================================================
// ERRORS
// ============================================================================

// ---------------------------------------------------------------------------
// TransferAuthority - accounts needed by `transfer_authority`
// ---------------------------------------------------------------------------
#[derive(Accounts)]
pub struct TransferAuthority<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, MandateConfig>,

    /// Operator rotation is an ADMIN action (ADR-017): the admin PDA must exist
    /// and the admin must sign. The operator key alone cannot rotate itself.
    #[account(
        seeds = [b"admin"],
        bump = admin_config.bump,
        has_one = admin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub admin: Signer<'info>,
}

#[error_code]
pub enum MandateError {
    #[msg("Mandate is already revoked")]
    AlreadyRevoked,

    /// Added 2026-09: appended, not inserted, so the numeric codes of the
    /// variants above are unchanged for anything already matching on them.
    #[msg("New authority cannot be the zero address")]
    InvalidAuthority,
}
