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
  });

  it("initializes with correct authority", async () => {
    const config = await program.account.registryConfig.fetch(configPda);
    expect(config.authority.toString()).to.equal(authority.publicKey.toString());
  });

  it("registers an agent successfully", async () => {
    const agentId = makeId("reg");
    const party = Keypair.generate().publicKey;
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);

    const before = (await program.account.registryConfig.fetch(configPda)).totalAgents.toNumber();

    await program.methods
      .registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), party)
      .accounts({ agent: agentPda })
      .rpc();

    const didHash = makeDidHash(agentId);
    const agent = await program.account.agent.fetch(agentPda);
    expect(Buffer.from(agent.agentId)).to.deep.equal(agentId);
    expect(Buffer.from(agent.didHash)).to.deep.equal(didHash);
    expect(agent.responsibleParty.toString()).to.equal(party.toString());
    expect(agent.revoked).to.be.false;
    expect(agent.revokedAt).to.be.null;
    expect(agent.registeredAt.toNumber()).to.be.greaterThan(0);

    const after = (await program.account.registryConfig.fetch(configPda)).totalAgents.toNumber();
    expect(after).to.equal(before + 1);
  });

  it("fails to register duplicate agent_id", async () => {
    const agentId = makeId("dup");
    const party = Keypair.generate().publicKey;
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);

    await program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), party).accounts({ agent: agentPda }).rpc();

    await expectFail(
      () => program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), party).accounts({ agent: agentPda }).rpc(),
      "already in use", "custom program error"
    );
  });

  it("rejects registration from unauthorized wallet", async () => {
    const agentId = makeId("unauth");
    const party = Keypair.generate().publicKey;
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);
    const imposter = Keypair.generate();
    await fund(provider.connection, imposter.publicKey);

    await expectFail(
      () => program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), party)
        .accounts({ agent: agentPda, authority: imposter.publicKey })
        .signers([imposter]).rpc(),
      "ConstraintHasOne", "Constraint", "has_one", "failed"
    );
  });

  it("revokes an agent successfully", async () => {
    const agentId = makeId("rev");
    const party = Keypair.generate().publicKey;
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);

    await program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), party).accounts({ agent: agentPda }).rpc();
    await program.methods.revokeAgent(Array.from(agentId)).accounts({ agent: agentPda }).rpc();

    const agent = await program.account.agent.fetch(agentPda);
    expect(agent.revoked).to.be.true;
    expect(agent.revokedAt).to.not.be.null;
  });

  it("fails to revoke already-revoked agent", async () => {
    const agentId = makeId("dbl-rev");
    const party = Keypair.generate().publicKey;
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);

    await program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), party).accounts({ agent: agentPda }).rpc();
    await program.methods.revokeAgent(Array.from(agentId)).accounts({ agent: agentPda }).rpc();

    await expectFail(
      () => program.methods.revokeAgent(Array.from(agentId)).accounts({ agent: agentPda }).rpc(),
      "AlreadyRevoked"
    );
  });

  it("rejects revocation from unauthorized wallet", async () => {
    const agentId = makeId("unauth-rev");
    const party = Keypair.generate().publicKey;
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);
    const imposter = Keypair.generate();
    await fund(provider.connection, imposter.publicKey);

    await program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), party).accounts({ agent: agentPda }).rpc();

    await expectFail(
      () => program.methods.revokeAgent(Array.from(agentId))
        .accounts({ agent: agentPda, authority: imposter.publicKey })
        .signers([imposter]).rpc(),
      "ConstraintHasOne", "Constraint", "has_one", "failed"
    );
  });

  it("transfers authority and transfers back", async () => {
    const newAuth = Keypair.generate();
    await fund(provider.connection, newAuth.publicKey);

    await program.methods.transferAuthority(newAuth.publicKey).rpc();
    let config = await program.account.registryConfig.fetch(configPda);
    expect(config.authority.toString()).to.equal(newAuth.publicKey.toString());

    await program.methods.transferAuthority(authority.publicKey)
      .accounts({ authority: newAuth.publicKey }).signers([newAuth]).rpc();
    config = await program.account.registryConfig.fetch(configPda);
    expect(config.authority.toString()).to.equal(authority.publicKey.toString());
  });

  it("rejects transfer to zero pubkey", async () => {
    await expectFail(
      () => program.methods.transferAuthority(PublicKey.default).rpc(),
      "InvalidAuthority"
    );
  });

  it("allows anyone to read agent data", async () => {
    const agentId = makeId("read");
    const party = Keypair.generate().publicKey;
    const agentPda = findPda([Buffer.from("agent"), agentId], program.programId);

    await program.methods.registerAgent(Array.from(agentId), Array.from(makeDidHash(agentId)), party).accounts({ agent: agentPda }).rpc();

    const agent = await program.account.agent.fetch(agentPda);
    expect(agent.responsibleParty.toString()).to.equal(party.toString());
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

  before(async () => {
    try { await program.methods.initialize().rpc(); } catch (_) {}
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
