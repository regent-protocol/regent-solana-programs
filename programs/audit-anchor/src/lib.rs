// ============================================================================
// Audit Anchor — Solana Program
// ============================================================================
//
// PURPOSE:
//   Stores Merkle roots on-chain as tamper-proof proof that a batch of
//   audit events existed at a specific point in time.
//
// HOW IT WORKS:
//   1. Off-chain: Regent collects up to 1,000 audit events
//   2. Off-chain: Each event is SHA-256 hashed
//   3. Off-chain: Hashes are arranged into a Merkle tree
//   4. Off-chain: The Merkle ROOT (32 bytes) is computed
//   5. ON-CHAIN: This program stores the root + metadata
//   6. Later: Anyone can verify any single event by providing a Merkle
//      proof against the on-chain root. If the proof checks out, the
//      event is authentic and unaltered.
//
// WHY THIS IS THE MOST IMPORTANT PROGRAM:
//   This is the core of the "tamper-proof" claim. Without this program,
//   Regent's audit trail is just a database that Regent controls.
//   With it, the audit trail has a cryptographic anchor that nobody
//   (including Regent) can alter.
//
// STORAGE:
//   Each batch becomes a separate PDA account, addressed by batch_id.
//   Reading a batch is free ($0). Writing costs ~$0.003 (rent + tx fee).
//
// EFFICIENCY:
//   - 10,000 events/day → ~10 on-chain writes/day (batched)
//   - Monthly cost: ~$0.15
//   - Each write stores just 32 bytes of Merkle root + metadata
//
// SIZE: ~120 lines including comments.
// ============================================================================

use anchor_lang::prelude::*;

declare_id!("8N1PpbJZKmvJjG86XWpP82XrWzp8HY5FHZuzyQTgjJas");

#[program]
pub mod audit_anchor {
    use super::*;

    // ------------------------------------------------------------------------
    // initialize — one-time setup: set the anchor authority
    // ------------------------------------------------------------------------
    pub fn initialize(ctx: Context<InitializeAnchorConfig>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.total_batches = 0;
        config.total_events_anchored = 0;

        msg!("AuditAnchor initialized. Authority: {}", config.authority);
        Ok(())
    }

    // ------------------------------------------------------------------------
    // anchor_batch — store a Merkle root on-chain
    // ------------------------------------------------------------------------
    // This is called by blockchain-worker after:
    //   1. Collecting a batch of audit events
    //   2. Computing the Merkle tree
    //   3. Encrypting and submitting to Celestia (data availability)
    //   4. Finally, anchoring the root HERE for immutability
    //
    // PARAMS:
    //   batch_id    — unique identifier for this batch (from PostgreSQL UUID)
    //   merkle_root — the 32-byte root hash of the Merkle tree
    //   event_count — how many events are in this batch (for analytics)
    //
    // SECURITY:
    //   - Only the authority can anchor (prevents spam)
    //   - Same batch_id cannot be anchored twice (PDA init fails)
    //   - event_count must be > 0 (empty batches are meaningless)
    //
    // WHAT A VERIFIER DOES LATER:
    //   1. Fetch this account by PDA: seeds = ["batch", batch_id]
    //   2. Read the merkle_root
    //   3. Take any single event from the batch
    //   4. Compute the Merkle proof (chain of sibling hashes)
    //   5. Verify: hash(event, proof) == merkle_root
    //   6. If it matches → the event is authentic and was part of this batch
    // ------------------------------------------------------------------------
    pub fn anchor_batch(
        ctx: Context<AnchorBatch>,
        batch_id: [u8; 32],
        merkle_root: [u8; 32],
        event_count: u32,
    ) -> Result<()> {
        // Guard: don't anchor empty batches
        require!(event_count > 0, AnchorError::EmptyBatch);

        // Guard: merkle_root must not be all zeros (would indicate a bug)
        require!(
            merkle_root != [0u8; 32],
            AnchorError::InvalidMerkleRoot
        );

        let batch = &mut ctx.accounts.batch;
        let clock = Clock::get()?;

        batch.batch_id = batch_id;
        batch.merkle_root = merkle_root;
        batch.event_count = event_count;
        batch.anchored_at = clock.unix_timestamp;
        batch.bump = ctx.bumps.batch;

        // Update global counters
        let config = &mut ctx.accounts.config;
        config.total_batches = config.total_batches.checked_add(1).unwrap();
        config.total_events_anchored = config
            .total_events_anchored
            .checked_add(event_count as u64)
            .unwrap();

        emit!(BatchAnchored {
            batch_id,
            merkle_root,
            event_count,
            timestamp: clock.unix_timestamp,
        });

        msg!(
            "Batch anchored: events={}, root={:?}",
            event_count,
            &merkle_root[..8] // log first 8 bytes for brevity
        );
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
            AnchorError::InvalidAuthority
        );

        let config = &mut ctx.accounts.config;
        let old = config.authority;
        config.authority = new_authority;

        msg!("Authority transferred: {} -> {}", old, new_authority);
        Ok(())
    }
}

// ============================================================================
// ACCOUNT STRUCTS
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct AnchorConfig {
    /// The wallet authorized to anchor batches.
    pub authority: Pubkey,               // 32 bytes
    /// Total batches ever anchored.
    pub total_batches: u64,              // 8 bytes
    /// Total individual events across all batches.
    pub total_events_anchored: u64,      // 8 bytes
}
// Total: 8 + 32 + 8 + 8 = 56 bytes

#[account]
#[derive(InitSpace)]
pub struct Batch {
    /// Unique identifier for this batch (matches PostgreSQL batch UUID).
    pub batch_id: [u8; 32],              // 32 bytes
    /// The Merkle root — cryptographic summary of all events in this batch.
    /// Anyone can verify a single event against this root.
    pub merkle_root: [u8; 32],           // 32 bytes
    /// Number of events in this batch.
    pub event_count: u32,                // 4 bytes
    /// Unix timestamp when this batch was anchored on-chain.
    pub anchored_at: i64,                // 8 bytes
    /// PDA bump seed.
    pub bump: u8,                        // 1 byte
}
// Total: 8 + 32 + 32 + 4 + 8 + 1 = 85 bytes

// ============================================================================
// INSTRUCTION ACCOUNT CONTEXTS
// ============================================================================

#[derive(Accounts)]
pub struct InitializeAnchorConfig<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + AnchorConfig::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, AnchorConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(batch_id: [u8; 32])]
pub struct AnchorBatch<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump,
        has_one = authority
    )]
    pub config: Account<'info, AnchorConfig>,

    // Each batch gets its own PDA account.
    // If the same batch_id is submitted twice, `init` fails automatically.
    #[account(
        init,
        payer = authority,
        space = 8 + Batch::INIT_SPACE,
        seeds = [b"batch", batch_id.as_ref()],
        bump
    )]
    pub batch: Account<'info, Batch>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// EVENTS
// ============================================================================

#[event]
pub struct BatchAnchored {
    pub batch_id: [u8; 32],
    pub merkle_root: [u8; 32],
    pub event_count: u32,
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
        bump,
        has_one = authority
    )]
    pub config: Account<'info, AnchorConfig>,

    pub authority: Signer<'info>,
}

#[error_code]
pub enum AnchorError {
    /// Batch must contain at least one event.
    #[msg("Cannot anchor an empty batch (event_count must be > 0)")]
    EmptyBatch,

    /// Merkle root must not be all zeros — indicates a computation bug.
    #[msg("Merkle root cannot be all zeros")]
    InvalidMerkleRoot,

    /// Added 2026-09: appended, not inserted, so the numeric codes of the
    /// variants above are unchanged for anything already matching on them.
    #[msg("New authority cannot be the zero address")]
    InvalidAuthority,
}
