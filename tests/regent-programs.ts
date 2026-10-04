// ============================================================================
// Comprehensive Test Suite — All 3 Regent Solana Programs
// ============================================================================
//
// Anchor 0.31.1 — explicitly pass PDA accounts to avoid seed mismatch
// between Anchor's Borsh-serialized arg resolution and raw seed bytes.
// ============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair } from "@solana/web3.js";
import { expect } from "chai";
import { createHash } from "crypto";

import { AgentRegistry } from "../target/types/agent_registry";
import { AuditAnchor } from "../target/types/audit_anchor";
import { MandateRegistry } from "../target/types/mandate_registry";

// ============================================================================
// HELPERS
// ============================================================================

function makeId(label: string): Buffer {
  const unique = label + "-" + Date.now() + "-" + Math.random();
  return createHash("sha256").update(unique).digest().subarray(0, 32);
}

function makeDidHash(agentId: Buffer, chain: string = "solana"): Buffer {
  const didString = `did:regent:${chain}:agent_${agentId.toString("hex").slice(0, 48)}`;
  return createHash("sha256").update(didString).digest();
}

function findPda(seeds: Buffer[], programId: PublicKey): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(seeds, programId);
  return pda;
}

function u64le(n: number): Buffer {
  const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b;
}

function chainHead(prev: Buffer, root: Buffer, seq: number): Buffer {
  return createHash("sha256").update(Buffer.concat([prev, root, u64le(seq)])).digest();
}

async function fund(conn: anchor.web3.Connection, pk: PublicKey) {
  const sig = await conn.requestAirdrop(pk, 2_000_000_000);
  await conn.confirmTransaction(sig);
}

async function expectFail(fn: () => Promise<any>, ...patterns: string[]) {
  try {
    await fn();
    expect.fail("Should have thrown");
  } catch (e: any) {
    if (e.message === "Should have thrown") throw e;
    if (patterns.length === 0) return; // any error is fine
    const msg = e.toString() + " " + (e.logs ? e.logs.join(" ") : "");
    const found = patterns.some((p) => msg.includes(p));
    if (!found) {
      throw new Error(`Expected [${patterns.join("|")}], got:\n${msg.slice(0, 600)}`);
    }
  }
}

// ============================================================================
// AGENT REGISTRY — 10 tests
// ============================================================================
describe("agent-registry", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.AgentRegistry as Program<AgentRegistry>;
  const authority = provider.wallet as anchor.Wallet;
  const configPda = findPda([Buffer.from("config")], program.programId);

  before(async () => {
    try {
      await program.methods.initialize().rpc();
    } catch (e: any) {
      console.log("AgentRegistry init:", e.message?.slice(0, 100) || "skip");
    }
    try { await program.methods.initAdmin(authority.publicKey).rpc(); } catch (_) {}
  });

  it("initializes with correct authority", async () => {
    const config = await program.account.registryConfig.fetch(configPda);
    expect(config.authority.toString()).to.equal(authority.publicKey.toString());
  });

  it("registers an agent successfully", async () => {
    const agentId = makeId("reg");
    const party = makeId("owner");
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);

    const before = (await program.account.registryConfig.fetch(configPda)).totalAgents.toNumber();

    await program.methods
      .registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), Array.from(party))
      .accounts({ agent: agentPda })
      .rpc();

    const didHash = makeDidHash(agentId);
    const agent = await program.account.agent.fetch(agentPda);
    expect(Buffer.from(agent.agentId)).to.deep.equal(agentId);
    expect(Buffer.from(agent.didHash)).to.deep.equal(didHash);
    expect(Buffer.from(agent.ownerCommitment)).to.deep.equal(party);
    expect(agent.revoked).to.be.false;
    expect(agent.revokedAt).to.be.null;
    expect(agent.registeredAt.toNumber()).to.be.greaterThan(0);

    const after = (await program.account.registryConfig.fetch(configPda)).totalAgents.toNumber();
    expect(after).to.equal(before + 1);
  });

  it("fails to register duplicate agent_id", async () => {
    const agentId = makeId("dup");
    const party = makeId("owner");
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);

    await program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), Array.from(party)).accounts({ agent: agentPda }).rpc();

    await expectFail(
      () => program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), Array.from(party)).accounts({ agent: agentPda }).rpc(),
      "already in use", "custom program error"
    );
  });

  it("rejects registration from unauthorized wallet", async () => {
    const agentId = makeId("unauth");
    const party = makeId("owner");
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);
    const imposter = Keypair.generate();
    await fund(provider.connection, imposter.publicKey);

    await expectFail(
      () => program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), Array.from(party))
        .accounts({ agent: agentPda, authority: imposter.publicKey })
        .signers([imposter]).rpc(),
      "ConstraintHasOne", "Constraint", "has_one", "failed"
    );
  });

  it("revokes an agent successfully", async () => {
    const agentId = makeId("rev");
    const party = makeId("owner");
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);

    await program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), Array.from(party)).accounts({ agent: agentPda }).rpc();
    await program.methods.revokeAgent(Array.from(agentId)).accounts({ agent: agentPda }).rpc();

    const agent = await program.account.agent.fetch(agentPda);
    expect(agent.revoked).to.be.true;
    expect(agent.revokedAt).to.not.be.null;
  });

  it("fails to revoke already-revoked agent", async () => {
    const agentId = makeId("dbl-rev");
    const party = makeId("owner");
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);

    await program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), Array.from(party)).accounts({ agent: agentPda }).rpc();
    await program.methods.revokeAgent(Array.from(agentId)).accounts({ agent: agentPda }).rpc();

    await expectFail(
      () => program.methods.revokeAgent(Array.from(agentId)).accounts({ agent: agentPda }).rpc(),
      "AlreadyRevoked"
    );
  });

  it("rejects revocation from unauthorized wallet", async () => {
    const agentId = makeId("unauth-rev");
    const party = makeId("owner");
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);
    const imposter = Keypair.generate();
    await fund(provider.connection, imposter.publicKey);

    await program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), Array.from(party)).accounts({ agent: agentPda }).rpc();

    await expectFail(
      () => program.methods.revokeAgent(Array.from(agentId))
        .accounts({ agent: agentPda, authority: imposter.publicKey })
        .signers([imposter]).rpc(),
      "ConstraintHasOne", "Constraint", "has_one", "failed"
    );
  });

  it("admin rotates the operator and rotates it back", async () => {
    const newAuth = Keypair.generate();
    await fund(provider.connection, newAuth.publicKey);

    // the admin (test wallet) signs; the operator key is not involved
    await program.methods.transferAuthority(newAuth.publicKey).rpc();
    let config = await program.account.registryConfig.fetch(configPda);
    expect(config.authority.toString()).to.equal(newAuth.publicKey.toString());

    await program.methods.transferAuthority(authority.publicKey).rpc();
    config = await program.account.registryConfig.fetch(configPda);
    expect(config.authority.toString()).to.equal(authority.publicKey.toString());
  });

  it("rejects operator rotation without the admin signature", async () => {
    const imposter = Keypair.generate();
    await fund(provider.connection, imposter.publicKey);
    await expectFail(
      () => program.methods.transferAuthority(imposter.publicKey)
        .accounts({ admin: imposter.publicKey }).signers([imposter]).rpc(),
      "ConstraintHasOne", "Constraint", "has_one", "failed"
    );
  });

  it("rejects transfer to zero pubkey", async () => {
    await expectFail(
      () => program.methods.transferAuthority(PublicKey.default).rpc(),
      "InvalidAuthority"
    );
  });

  it("init_admin runs once; transfer_admin hands over and back", async () => {
    await expectFail(() => program.methods.initAdmin(authority.publicKey).rpc(), "already in use", "custom program error");
    const adminPda = findPda([Buffer.from("admin")], program.programId);
    const next = Keypair.generate();
    await fund(provider.connection, next.publicKey);
    await program.methods.transferAdmin(next.publicKey).rpc();
    expect((await program.account.adminConfig.fetch(adminPda)).admin.toString()).to.equal(next.publicKey.toString());
    // the old admin can no longer rotate the operator
    await expectFail(() => program.methods.transferAuthority(authority.publicKey).rpc(), "ConstraintHasOne", "Constraint", "has_one", "failed");
    await program.methods.transferAdmin(authority.publicKey).accounts({ admin: next.publicKey }).signers([next]).rpc();
    expect((await program.account.adminConfig.fetch(adminPda)).admin.toString()).to.equal(authority.publicKey.toString());
  });

  it("allows anyone to read agent data", async () => {
    const agentId = makeId("read");
    const party = makeId("owner");
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);

    await program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), Array.from(party)).accounts({ agent: agentPda }).rpc();

    const agent = await program.account.agent.fetch(agentPda);
    expect(Buffer.from(agent.ownerCommitment)).to.deep.equal(party);
  });
});

// ============================================================================
// AUDIT ANCHOR — 6 tests
// ============================================================================
describe("audit-anchor", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.AuditAnchor as Program<AuditAnchor>;
  const configPda = findPda([Buffer.from("config")], program.programId);

  const chainPda = findPda([Buffer.from("chain")], program.programId);
  const epochPda = (i: number) => findPda([Buffer.from("epoch"), u64le(i)], program.programId);

  before(async () => {
    try { await program.methods.initialize().rpc(); } catch (_) {}
    try { await program.methods.initAdmin(provider.wallet.publicKey).rpc(); } catch (_) {}
    try { await program.methods.initChain().rpc(); } catch (_) {}
  });

  it("chain starts at seq 0 with a zero head", async () => {
    const chain = await program.account.auditChain.fetch(chainPda);
    expect(chain.seq.toNumber()).to.equal(0);
    expect(Buffer.from(chain.head)).to.deep.equal(Buffer.alloc(32));
  });

  it("appends batches strictly in sequence and chains the head", async () => {
    const r1 = makeId("root-1"), r2 = makeId("root-2");
    await program.methods.appendBatch(Array.from(r1), new anchor.BN(1), Array.from(Buffer.alloc(32))).rpc();
    let chain = await program.account.auditChain.fetch(chainPda);
    const h1 = chainHead(Buffer.alloc(32), r1, 1);
    expect(Buffer.from(chain.head)).to.deep.equal(h1);
    expect(chain.seq.toNumber()).to.equal(1);

    await program.methods.appendBatch(Array.from(r2), new anchor.BN(2), Array.from(h1)).rpc();
    chain = await program.account.auditChain.fetch(chainPda);
    expect(Buffer.from(chain.head)).to.deep.equal(chainHead(h1, r2, 2));
    expect(chain.lastAppendedAt.toNumber()).to.be.greaterThan(0);
  });

  it("rejects a replayed or skipped seq", async () => {
    const r = makeId("root-x");
    const head = Array.from((await program.account.auditChain.fetch(chainPda)).head);
    await expectFail(() => program.methods.appendBatch(Array.from(r), new anchor.BN(2), head).rpc(), "SequenceMismatch");
    await expectFail(() => program.methods.appendBatch(Array.from(r), new anchor.BN(4), head).rpc(), "SequenceMismatch");
    await expectFail(() => program.methods.appendBatch(new Array(32).fill(0), new anchor.BN(3), head).rpc(), "InvalidMerkleRoot");
  });

  it("rejects an append that claims the wrong previous head", async () => {
    const wrong = Array.from(makeId("not-the-head"));
    await expectFail(
      () => program.methods.appendBatch(Array.from(makeId("root-y")), new anchor.BN(3), wrong).rpc(),
      "HeadMismatch"
    );
  });

  it("rejects an append from a non-operator", async () => {
    const head = Array.from((await program.account.auditChain.fetch(chainPda)).head);
    const imposter = Keypair.generate();
    await fund(provider.connection, imposter.publicKey);
    await expectFail(
      () => program.methods.appendBatch(Array.from(makeId("r")), new anchor.BN(3), head)
        .accounts({ authority: imposter.publicKey }).signers([imposter]).rpc(),
      "ConstraintHasOne", "Constraint", "has_one", "failed"
    );
  });

  it("anchors a contiguous epoch over the appended range", async () => {
    const root = makeId("epoch-1");
    await program.methods.anchorEpoch(new anchor.BN(1), new anchor.BN(1), new anchor.BN(2), Array.from(root))
      .accounts({ epoch: epochPda(1) }).rpc();
    const epoch = await program.account.epoch.fetch(epochPda(1));
    expect(epoch.firstSeq.toNumber()).to.equal(1);
    expect(epoch.lastSeq.toNumber()).to.equal(2);
    expect(Buffer.from(epoch.merkleRoot)).to.deep.equal(root);
    const chain = await program.account.auditChain.fetch(chainPda);
    expect(chain.epochCount.toNumber()).to.equal(1);
    expect(chain.lastEpochEndSeq.toNumber()).to.equal(2);
  });

  it("rejects epochs that are out of order, non-contiguous or beyond the head", async () => {
    const root = makeId("epoch-bad");
    await expectFail(() => program.methods.anchorEpoch(new anchor.BN(1), new anchor.BN(3), new anchor.BN(3), Array.from(root))
      .accounts({ epoch: epochPda(1) }).rpc(), "already in use", "custom program error", "EpochIndexMismatch");
    await expectFail(() => program.methods.anchorEpoch(new anchor.BN(2), new anchor.BN(4), new anchor.BN(4), Array.from(root))
      .accounts({ epoch: epochPda(2) }).rpc(), "EpochNotContiguous");
    await expectFail(() => program.methods.anchorEpoch(new anchor.BN(2), new anchor.BN(3), new anchor.BN(9), Array.from(root))
      .accounts({ epoch: epochPda(2) }).rpc(), "EpochOutOfRange");
    // a valid second epoch after one more append
    const head3 = Array.from((await program.account.auditChain.fetch(chainPda)).head);
    await program.methods.appendBatch(Array.from(makeId("root-3")), new anchor.BN(3), head3).rpc();
    await program.methods.anchorEpoch(new anchor.BN(2), new anchor.BN(3), new anchor.BN(3), Array.from(root))
      .accounts({ epoch: epochPda(2) }).rpc();
    expect((await program.account.auditChain.fetch(chainPda)).epochCount.toNumber()).to.equal(2);
  });

  it("anchors a batch with valid Merkle root", async () => {
    const batchId = makeId("b-ok");
    const merkleRoot = makeId("m-ok");
    const batchPda = findPda([Buffer.from("batch"), batchId], program.programId);

    const before = await program.account.anchorConfig.fetch(configPda);

    await program.methods
      .anchorBatch(Array.from(batchId), Array.from(merkleRoot), 42)
      .accounts({ batch: batchPda })
      .rpc();

    const batch = await program.account.batch.fetch(batchPda);
    expect(Buffer.from(batch.batchId)).to.deep.equal(batchId);
    expect(Buffer.from(batch.merkleRoot)).to.deep.equal(merkleRoot);
    expect(batch.eventCount).to.equal(42);
    expect(batch.anchoredAt.toNumber()).to.be.greaterThan(0);

    const after = await program.account.anchorConfig.fetch(configPda);
    expect(after.totalBatches.toNumber()).to.equal(before.totalBatches.toNumber() + 1);
    expect(after.totalEventsAnchored.toNumber()).to.equal(before.totalEventsAnchored.toNumber() + 42);
  });

  it("fails to anchor duplicate batch_id", async () => {
    const batchId = makeId("b-dup");
    const root = makeId("m-dup");
    const batchPda = findPda([Buffer.from("batch"), batchId], program.programId);

    await program.methods.anchorBatch(Array.from(batchId), Array.from(root), 10).accounts({ batch: batchPda }).rpc();

    await expectFail(
      () => program.methods.anchorBatch(Array.from(batchId), Array.from(root), 10).accounts({ batch: batchPda }).rpc(),
      "already in use", "custom program error"
    );
  });

  it("rejects batch with event_count = 0", async () => {
    const batchId = makeId("b-empty");
    const root = makeId("m-empty");
    const batchPda = findPda([Buffer.from("batch"), batchId], program.programId);

    await expectFail(
      () => program.methods.anchorBatch(Array.from(batchId), Array.from(root), 0).accounts({ batch: batchPda }).rpc(),
      "EmptyBatch"
    );
  });

  it("rejects batch with all-zero Merkle root", async () => {
    const batchId = makeId("b-zero");
    const zeroRoot = new Array(32).fill(0);
    const batchPda = findPda([Buffer.from("batch"), batchId], program.programId);

    await expectFail(
      () => program.methods.anchorBatch(Array.from(batchId), zeroRoot, 10).accounts({ batch: batchPda }).rpc(),
      "InvalidMerkleRoot"
    );
  });

  it("rejects anchoring from unauthorized wallet", async () => {
    const batchId = makeId("b-unauth");
    const root = makeId("m-unauth");
    const batchPda = findPda([Buffer.from("batch"), batchId], program.programId);
    const imposter = Keypair.generate();
    await fund(provider.connection, imposter.publicKey);

    await expectFail(
      () => program.methods.anchorBatch(Array.from(batchId), Array.from(root), 5)
        .accounts({ batch: batchPda, authority: imposter.publicKey })
        .signers([imposter]).rpc(),
      "ConstraintHasOne", "Constraint", "has_one", "failed"
    );
  });

  it("anchors batch with large event count (1000)", async () => {
    const batchId = makeId("b-max");
    const root = makeId("m-max");
    const batchPda = findPda([Buffer.from("batch"), batchId], program.programId);

    await program.methods.anchorBatch(Array.from(batchId), Array.from(root), 1000).accounts({ batch: batchPda }).rpc();

    const batch = await program.account.batch.fetch(batchPda);
    expect(batch.eventCount).to.equal(1000);
  });
});

// ============================================================================
// MANDATE REGISTRY — 7 tests
// ============================================================================
describe("mandate-registry", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.MandateRegistry as Program<MandateRegistry>;
  const configPda = findPda([Buffer.from("config")], program.programId);

  before(async () => {
    try { await program.methods.initialize().rpc(); } catch (_) {}
    try { await program.methods.initAdmin(provider.wallet.publicKey).rpc(); } catch (_) {}
  });

  it("registers a mandate linked to an agent", async () => {
    const mandateId = makeId("m-ok");
    const agentId = makeId("a-for-m");
    const mandatePda = findPda([Buffer.from("mandate"), mandateId], program.programId);

    await program.methods.registerMandate(Array.from(mandateId), Array.from(agentId))
      .accounts({ mandate: mandatePda }).rpc();

    const mandate = await program.account.mandate.fetch(mandatePda);
    expect(Buffer.from(mandate.mandateId)).to.deep.equal(mandateId);
    expect(Buffer.from(mandate.agentId)).to.deep.equal(agentId);
    expect(mandate.revoked).to.be.false;
    expect(mandate.revokedAt).to.be.null;
  });

  it("allows multiple mandates for same agent", async () => {
    const agentId = makeId("a-multi");
    const m1 = makeId("m-multi-1");
    const m2 = makeId("m-multi-2");
    const pda1 = findPda([Buffer.from("mandate"), m1], program.programId);
    const pda2 = findPda([Buffer.from("mandate"), m2], program.programId);

    await program.methods.registerMandate(Array.from(m1), Array.from(agentId)).accounts({ mandate: pda1 }).rpc();
    await program.methods.registerMandate(Array.from(m2), Array.from(agentId)).accounts({ mandate: pda2 }).rpc();

    const mandate1 = await program.account.mandate.fetch(pda1);
    const mandate2 = await program.account.mandate.fetch(pda2);
    expect(Buffer.from(mandate1.agentId)).to.deep.equal(agentId);
    expect(Buffer.from(mandate2.agentId)).to.deep.equal(agentId);
  });

  it("fails to register duplicate mandate_id", async () => {
    const mandateId = makeId("m-dup");
    const agentId = makeId("a-dup-m");
    const mandatePda = findPda([Buffer.from("mandate"), mandateId], program.programId);

    await program.methods.registerMandate(Array.from(mandateId), Array.from(agentId)).accounts({ mandate: mandatePda }).rpc();

    await expectFail(
      () => program.methods.registerMandate(Array.from(mandateId), Array.from(agentId)).accounts({ mandate: mandatePda }).rpc(),
      "already in use", "custom program error"
    );
  });

  it("revokes a mandate successfully", async () => {
    const mandateId = makeId("m-rev");
    const agentId = makeId("a-rev-m");
    const mandatePda = findPda([Buffer.from("mandate"), mandateId], program.programId);

    await program.methods.registerMandate(Array.from(mandateId), Array.from(agentId)).accounts({ mandate: mandatePda }).rpc();
    await program.methods.revokeMandate(Array.from(mandateId)).accounts({ mandate: mandatePda }).rpc();

    const mandate = await program.account.mandate.fetch(mandatePda);
    expect(mandate.revoked).to.be.true;
    expect(mandate.revokedAt).to.not.be.null;
  });

  it("fails to revoke already-revoked mandate", async () => {
    const mandateId = makeId("m-dbl");
    const agentId = makeId("a-dbl-m");
    const mandatePda = findPda([Buffer.from("mandate"), mandateId], program.programId);

    await program.methods.registerMandate(Array.from(mandateId), Array.from(agentId)).accounts({ mandate: mandatePda }).rpc();
    await program.methods.revokeMandate(Array.from(mandateId)).accounts({ mandate: mandatePda }).rpc();

    await expectFail(
      () => program.methods.revokeMandate(Array.from(mandateId)).accounts({ mandate: mandatePda }).rpc(),
      "AlreadyRevoked"
    );
  });

  it("rejects registration from unauthorized wallet", async () => {
    const mandateId = makeId("m-unauth");
    const agentId = makeId("a-unauth-m");
    const mandatePda = findPda([Buffer.from("mandate"), mandateId], program.programId);
    const imposter = Keypair.generate();
    await fund(provider.connection, imposter.publicKey);

    await expectFail(
      () => program.methods.registerMandate(Array.from(mandateId), Array.from(agentId))
        .accounts({ mandate: mandatePda, authority: imposter.publicKey })
        .signers([imposter]).rpc(),
      "ConstraintHasOne", "Constraint", "has_one", "failed"
    );
  });

  it("increments total_mandates correctly", async () => {
    const before = (await program.account.mandateConfig.fetch(configPda)).totalMandates.toNumber();

    const mandateId = makeId("m-ctr");
    const agentId = makeId("a-ctr-m");
    const mandatePda = findPda([Buffer.from("mandate"), mandateId], program.programId);

    await program.methods.registerMandate(Array.from(mandateId), Array.from(agentId)).accounts({ mandate: mandatePda }).rpc();

    const after = (await program.account.mandateConfig.fetch(configPda)).totalMandates.toNumber();
    expect(after).to.equal(before + 1);
  });
});
