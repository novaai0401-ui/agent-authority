import { test } from "node:test";
import assert from "node:assert/strict";
import { createBehalf } from "../src/behalf.js";
import { newKeyPair, exportPublicKey } from "../src/crypto.js";

// ---- C3: cryptographic agent identity binding (SVID-style) ----
//
// A mandate granted with `bindAgent` carries an `agentKey` caveat. Authorizing
// it requires not only possession of the chain's terminal key but also a proof
// of possession of the bound agent's private key. This closes the gap where a
// stolen holder credential alone was enough to act.

test("a bound mandate authorizes when the agent identity is proven", async () => {
  const agent = newKeyPair();
  const issuer = createBehalf();
  const m = issuer.grant({
    principal: "u",
    agent: "research-agent",
    can: ["read:calendar"],
    expiresIn: "1h",
    bindAgent: exportPublicKey(agent.publicKey),
  });

  // The legitimate agent runs an engine configured with its identity key.
  const verifier = createBehalf({ trust: [issuer.publicKey], agentKey: agent });
  const proof = m.prove("read:calendar", { agentKeys: [agent] });
  await assert.doesNotReject(verifier.authorize(m.token, "read:calendar", proof));
});

test("the engine's own agentKey satisfies binding on the in-process holder path", async () => {
  const agent = newKeyPair();
  // One engine both issues and acts as the agent (carries the agent identity).
  const eng = createBehalf({ agentKey: agent });
  const m = eng.grant({
    principal: "u",
    agent: "a",
    can: ["read:calendar"],
    expiresIn: "1h",
    bindAgent: exportPublicKey(agent.publicKey),
  });
  await assert.doesNotReject(m.authorize("read:calendar"));
});

test("a stolen credential cannot authorize without the agent key (theft blocked)", async () => {
  const agent = newKeyPair();
  const issuer = createBehalf();
  const m = issuer.grant({
    principal: "u",
    agent: "a",
    can: ["read:calendar"],
    expiresIn: "1h",
    bindAgent: exportPublicKey(agent.publicKey),
  });

  // The thief exports/imports the full holder credential (token + delegation
  // key) but does NOT have the agent identity key.
  const thiefEngine = createBehalf({ trust: [issuer.publicKey] });
  const stolen = thiefEngine.import(m.serializeWithKey());
  assert.equal(stolen.canDelegate, true); // they hold the delegation key…

  // …yet a proof without the agent signature is rejected.
  const proof = stolen.prove("read:calendar");
  await assert.rejects(
    () => thiefEngine.authorize(stolen.token, "read:calendar", proof),
    /agent identity proof required/,
  );

  // Signing with the WRONG agent key also fails (not the bound identity).
  const wrong = newKeyPair();
  const forged = stolen.prove("read:calendar", { agentKeys: [wrong] });
  await assert.rejects(
    () => thiefEngine.authorize(stolen.token, "read:calendar", forged),
    /agent identity proof required/,
  );
});

test("a thief cannot bypass by appending their own binding (conjunctive)", async () => {
  const agent = newKeyPair();
  const issuer = createBehalf();
  const m = issuer.grant({
    principal: "u",
    agent: "a",
    can: ["read:calendar"],
    expiresIn: "1h",
    bindAgent: exportPublicKey(agent.publicKey),
  });

  const thiefEngine = createBehalf({ trust: [issuer.publicKey] });
  const stolen = thiefEngine.import(m.serializeWithKey());

  // The thief attenuates, adding their OWN agentKey binding, and signs with it.
  const thiefAgent = newKeyPair();
  const reBound = stolen.attenuate({ bindAgent: exportPublicKey(thiefAgent.publicKey) });
  const proof = reBound.prove("read:calendar", { agentKeys: [thiefAgent] });

  // The original agentKey caveat is still in the chain and unsatisfied: binding
  // is conjunctive, so appending one only adds a requirement.
  await assert.rejects(
    () => thiefEngine.authorize(reBound.token, "read:calendar", proof),
    /agent identity proof required/,
  );

  // Satisfying BOTH (legit + thief's) does authorize — proving conjunction, not
  // replacement. (In practice the thief never has the legit agent key.)
  const both = reBound.prove("read:calendar", { agentKeys: [agent, thiefAgent] });
  await assert.doesNotReject(thiefEngine.authorize(reBound.token, "read:calendar", both));
});

test("unbound mandates are unaffected (no agentKey caveat, no agent proof needed)", async () => {
  const issuer = createBehalf();
  const m = issuer.grant({ principal: "u", agent: "a", can: ["read:calendar"], expiresIn: "1h" });
  const verifier = createBehalf({ trust: [issuer.publicKey] });
  const proof = m.prove("read:calendar");
  await assert.doesNotReject(verifier.authorize(m.token, "read:calendar", proof));
});

test("agent binding survives attenuation across a trust boundary (present/authorize)", async () => {
  const agent = newKeyPair();
  const issuer = createBehalf();
  const m = issuer.grant({
    principal: "u",
    agent: "a",
    can: ["read:calendar", "read:email"],
    expiresIn: "1h",
    bindAgent: exportPublicKey(agent.publicKey),
  });
  const verifier = createBehalf({ trust: [issuer.publicKey] });

  // Holder narrows then presents; the inherited agentKey caveat must still be
  // satisfied with the agent key.
  const narrowed = m.attenuate({ can: ["read:calendar"], expiresIn: "10m" });
  const proof = narrowed.prove("read:calendar", { agentKeys: [agent] });
  await assert.doesNotReject(verifier.authorize(narrowed.token, "read:calendar", proof));

  // Without the agent key it is denied even after attenuation.
  const noAgent = narrowed.prove("read:calendar");
  await assert.rejects(
    () => verifier.authorize(narrowed.token, "read:calendar", noAgent),
    /agent identity proof required/,
  );
});
