'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { planRotation } = require('../src/planner');

const HOUR = 3600000;
const T0 = 1700000000000;

// 构造一个基础场景：两个服务互相调用，两个代理分属两个 rollout 波次。
function baseInput(overrides = {}) {
  return {
    now: T0,
    roundMs: HOUR,
    oldRootId: 'root-old',
    newRootId: 'root-new',
    newIntermediateId: 'ica-new',
    roots: [
      { id: 'root-old', status: 'active', notBefore: T0 - 100 * HOUR, notAfter: T0 + 9000 * HOUR },
      { id: 'root-new', status: 'active', notBefore: T0, notAfter: T0 + 9000 * HOUR },
    ],
    intermediates: [
      { id: 'ica-old', rootId: 'root-old', status: 'active' },
      { id: 'ica-new', rootId: 'root-new', status: 'active' },
    ],
    leaves: [
      {
        id: 'leaf-a',
        proxyId: 'proxy-a',
        intermediateId: 'ica-old',
        identityUri: 'spiffe://mesh/ns/default/sa/svc-a',
        notBefore: T0 - HOUR,
        notAfter: T0 + 24 * HOUR,
      },
      {
        id: 'leaf-b',
        proxyId: 'proxy-b',
        intermediateId: 'ica-old',
        identityUri: 'spiffe://mesh/ns/default/sa/svc-b',
        notBefore: T0 - HOUR,
        notAfter: T0 + 48 * HOUR,
      },
    ],
    proxies: [
      {
        id: 'proxy-a',
        service: 'svc-a',
        identityUri: 'spiffe://mesh/ns/default/sa/svc-a',
        wave: 1,
        trustBundle: ['root-old'],
        ack: { 'root-new': true },
      },
      {
        id: 'proxy-b',
        service: 'svc-b',
        identityUri: 'spiffe://mesh/ns/default/sa/svc-b',
        wave: 2,
        trustBundle: ['root-old'],
        ack: { 'root-new': true },
      },
    ],
    dependencies: [
      { caller: 'svc-a', callee: 'svc-b' },
      { caller: 'svc-b', callee: 'svc-a' },
    ],
    ...overrides,
  };
}

test('双根重叠：全部 ACK 后收敛，安全退役时间取最迟旧叶过期时间', () => {
  const plan = planRotation(baseInput());
  assert.equal(plan.status, 'planned');

  // 第 1 轮：proxy-a 获得新根进入双信任，proxy-b 仍只信旧根。
  const round1 = plan.rounds.find((r) => r.round === 1);
  const pa = round1.proxies.find((p) => p.id === 'proxy-a');
  const pb = round1.proxies.find((p) => p.id === 'proxy-b');
  assert.deepEqual(pa.trustBundle.sort(), ['root-new', 'root-old']);
  assert.deepEqual(pb.trustBundle, ['root-old']);
  assert.equal(pa.ackedNewRoot, true);

  // 双根重叠期内双方叶证书仍由旧根签发，不存在握手风险边。
  assert.equal(round1.riskyEdges.length, 0);

  // 第 2 轮后全部代理双信任，最终无风险边。
  const round2 = plan.rounds.find((r) => r.round === 2);
  assert.ok(round2.proxies.every((p) => p.ackedNewRoot));
  assert.equal(plan.riskyEdges.length, 0);

  // 退役时间 = 最迟旧叶过期（leaf-b, T0+48h）。
  assert.equal(plan.safeRetirementTime, T0 + 48 * HOUR);
  const retirePhase = plan.phases.find((p) => p.name === 'retire-old-root');
  assert.equal(retirePhase.status, 'ready');
});

test('部分 ACK：未 ACK 的代理阻止签发切换与旧根退役', () => {
  const input = baseInput();
  input.proxies[1].ack = { 'root-new': false };
  const plan = planRotation(input);

  assert.equal(plan.status, 'blocked');
  assert.equal(plan.safeRetirementTime, null);

  const switchPhase = plan.phases.find((p) => p.name === 'switch-issuance');
  assert.equal(switchPhase.status, 'blocked');
  assert.ok(switchPhase.blockers.some((b) => b.type === 'partial-ack'));
  assert.deepEqual(
    switchPhase.blockers.find((b) => b.type === 'partial-ack').proxyIds,
    ['proxy-b']
  );

  const retirePhase = plan.phases.find((p) => p.name === 'retire-old-root');
  assert.equal(retirePhase.status, 'blocked');
  assert.ok(retirePhase.blockers.some((b) => b.type === 'dual-trust-incomplete'));
});

test('缺失中间 CA：证书链不完整阻止签发切换', () => {
  const input = baseInput();
  // 新签发链的中间 CA 未登记。
  input.intermediates = input.intermediates.filter((i) => i.id !== 'ica-new');
  const plan = planRotation(input);

  assert.equal(plan.status, 'blocked');
  const switchPhase = plan.phases.find((p) => p.name === 'switch-issuance');
  assert.equal(switchPhase.status, 'blocked');
  assert.ok(switchPhase.blockers.some((b) => b.type === 'missing-intermediate-ca'));
  assert.equal(plan.safeRetirementTime, null);
});

test('回滚：代理 NACK 触发回滚，信任包恢复旧根单信任', () => {
  const input = baseInput({ rollbackOnNack: true });
  input.proxies[1].ack = {};
  input.proxies[1].nack = ['root-new'];
  const plan = planRotation(input);

  assert.equal(plan.status, 'rolled-back');
  const rollbackRound = plan.rounds.find((r) => r.phase === 'rollback');
  assert.ok(rollbackRound, '应存在回滚轮次');
  for (const p of rollbackRound.proxies) {
    assert.deepEqual(p.trustBundle, ['root-old']);
    assert.equal(p.ackedNewRoot, false);
  }
  // 回滚后所有阶段均标记 rolled-back，无退役时间。
  assert.ok(plan.phases.every((p) => p.status === 'rolled-back'));
  assert.equal(plan.safeRetirementTime, null);
});

test('身份 URI 不匹配：阻止签发切换与旧根退役', () => {
  const input = baseInput();
  input.leaves[1].identityUri = 'spiffe://mesh/ns/default/sa/svc-c';
  const plan = planRotation(input);

  assert.equal(plan.status, 'blocked');
  const mismatch = plan.blockers.find((b) => b.type === 'identity-uri-mismatch');
  assert.ok(mismatch);
  assert.equal(mismatch.proxyId, 'proxy-b');
  assert.equal(mismatch.expected, 'spiffe://mesh/ns/default/sa/svc-b');
  assert.equal(mismatch.actual, 'spiffe://mesh/ns/default/sa/svc-c');
  assert.equal(plan.safeRetirementTime, null);
});

test('签发者停用：新中间 CA 已停用则阻止签发切换', () => {
  const input = baseInput();
  input.intermediates.find((i) => i.id === 'ica-new').status = 'deactivated';
  const plan = planRotation(input);

  assert.equal(plan.status, 'blocked');
  const switchPhase = plan.phases.find((p) => p.name === 'switch-issuance');
  assert.ok(switchPhase.blockers.some((b) => b.type === 'issuer-deactivated'));
  assert.equal(plan.safeRetirementTime, null);
});

test('NACK 但不回滚：分发阶段被阻塞，信任包保持双根但不收敛', () => {
  const input = baseInput();
  input.proxies[1].ack = {};
  input.proxies[1].nack = ['root-new'];
  const plan = planRotation(input);

  assert.equal(plan.status, 'blocked');
  const distribute = plan.phases.find((p) => p.name === 'distribute-new-root');
  assert.equal(distribute.status, 'blocked');
  assert.ok(distribute.blockers.some((b) => b.type === 'proxy-nack'));
  assert.equal(plan.safeRetirementTime, null);
});
