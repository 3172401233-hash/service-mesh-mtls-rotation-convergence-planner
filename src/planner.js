'use strict';

/**
 * mTLS 轮换收敛规划器。
 *
 * 只处理抽象的证书元数据（ID、有效期、状态、身份 URI、信任包内容），
 * 不接触、不保存任何私钥或证书 DER/PEM 内容。
 *
 * 阶段：
 *   1. distribute-new-root  按 rollout 波次把新根推进代理信任包
 *   2. dual-trust           全部代理 ACK 新根，进入新旧双信任
 *   3. switch-issuance      签发切换到新中间 CA / 新根
 *   4. retire-old-root      所有调用方向双向具备新信任且旧叶证书全部过期后退役旧根
 */

const PHASE_DISTRIBUTE = 'distribute-new-root';
const PHASE_DUAL_TRUST = 'dual-trust';
const PHASE_SWITCH = 'switch-issuance';
const PHASE_RETIRE = 'retire-old-root';

function rootOfLeaf(leaf, intermediates) {
  const ica = intermediates.get(leaf.intermediateId);
  return ica ? ica.rootId : null;
}

function chainBlockersForLeaf(leaf, intermediates, roots) {
  const blockers = [];
  const ica = intermediates.get(leaf.intermediateId);
  if (!ica) {
    blockers.push({
      type: 'missing-intermediate-ca',
      leafId: leaf.id,
      intermediateId: leaf.intermediateId,
      message: `叶证书 ${leaf.id} 的证书链缺少中间 CA ${leaf.intermediateId}`,
    });
    return blockers;
  }
  if (ica.status === 'deactivated') {
    blockers.push({
      type: 'issuer-deactivated',
      issuerId: ica.id,
      leafId: leaf.id,
      message: `中间 CA ${ica.id} 已停用，无法作为签发者`,
    });
  }
  const root = roots.get(ica.rootId);
  if (!root) {
    blockers.push({
      type: 'missing-intermediate-ca',
      leafId: leaf.id,
      intermediateId: ica.id,
      message: `中间 CA ${ica.id} 的上级根 ${ica.rootId} 不存在，证书链不完整`,
    });
  } else if (root.status === 'deactivated') {
    blockers.push({
      type: 'issuer-deactivated',
      issuerId: root.id,
      leafId: leaf.id,
      message: `根证书 ${root.id} 已停用，无法作为签发者`,
    });
  }
  return blockers;
}

/**
 * 计算某一时刻所有调用边的风险。
 * mTLS 双向握手：调用方要验证被调方的叶证书，被调方也要验证调用方的叶证书。
 * 任一侧呈现的叶证书所属根不在对方信任包中，该边即为风险边。
 */
function computeRiskyEdges(dependencies, proxiesByService, leafByProxy, intermediates) {
  const risky = [];
  for (const dep of dependencies) {
    const callers = proxiesByService.get(dep.caller) || [];
    const callees = proxiesByService.get(dep.callee) || [];
    for (const caller of callers) {
      for (const callee of callees) {
        const reasons = [];
        const calleeLeaf = leafByProxy.get(callee.id);
        const callerLeaf = leafByProxy.get(caller.id);
        if (calleeLeaf) {
          const root = rootOfLeaf(calleeLeaf, intermediates);
          if (!root || !caller.trustBundle.includes(root)) {
            reasons.push(
              `被调方 ${callee.id} 呈现的叶证书根 ${root || '(未知)'} 不在调用方 ${caller.id} 的信任包中`
            );
          }
        }
        if (callerLeaf) {
          const root = rootOfLeaf(callerLeaf, intermediates);
          if (!root || !callee.trustBundle.includes(root)) {
            reasons.push(
              `调用方 ${caller.id} 呈现的叶证书根 ${root || '(未知)'} 不在被调方 ${callee.id} 的信任包中`
            );
          }
        }
        if (reasons.length > 0) {
          risky.push({
            caller: dep.caller,
            callee: dep.callee,
            callerProxy: caller.id,
            calleeProxy: callee.id,
            reasons,
          });
        }
      }
    }
  }
  return risky;
}

/**
 * 主入口：根据输入元数据规划轮换收敛。
 * @param {object} input 见 README 的输入 schema
 * @returns {object} 规划结果：每轮代理信任状态、风险调用边、安全退役时间、阶段与阻塞项
 */
function planRotation(input) {
  const now = input.now ?? 0;
  const roundMs = input.roundMs ?? 3600000;
  const rollbackOnNack = Boolean(input.rollbackOnNack);

  const oldRootId = input.oldRootId;
  const newRootId = input.newRootId;
  const newIntermediateId = input.newIntermediateId;

  const roots = new Map((input.roots || []).map((r) => [r.id, r]));
  const intermediates = new Map((input.intermediates || []).map((i) => [i.id, i]));
  const leaves = input.leaves || [];
  const dependencies = input.dependencies || [];

  const proxies = (input.proxies || []).map((p) => ({
    id: p.id,
    service: p.service,
    identityUri: p.identityUri,
    wave: p.wave ?? 1,
    trustBundle: [...(p.trustBundle || [])],
    ackedNew: false,
    nackedNew: (p.nack || []).includes(newRootId),
    ack: p.ack || {},
  }));

  const proxiesByService = new Map();
  for (const proxy of proxies) {
    if (!proxiesByService.has(proxy.service)) proxiesByService.set(proxy.service, []);
    proxiesByService.get(proxy.service).push(proxy);
  }

  // 当前生效叶证书（切换签发前都是旧叶）。
  const leafByProxy = new Map();
  for (const leaf of leaves) {
    if (leaf.proxyId) leafByProxy.set(leaf.proxyId, leaf);
  }

  // ---- 静态阻塞项：身份 URI 不匹配、证书链缺中间 CA、签发者停用 ----
  const blockers = [];
  for (const proxy of proxies) {
    const leaf = leafByProxy.get(proxy.id);
    if (!leaf) continue;
    if (proxy.identityUri && leaf.identityUri !== proxy.identityUri) {
      blockers.push({
        type: 'identity-uri-mismatch',
        proxyId: proxy.id,
        leafId: leaf.id,
        expected: proxy.identityUri,
        actual: leaf.identityUri,
        message: `代理 ${proxy.id} 期望身份 ${proxy.identityUri}，叶证书 ${leaf.id} 实际身份 ${leaf.identityUri}`,
      });
    }
    for (const b of chainBlockersForLeaf(leaf, intermediates, roots)) {
      blockers.push({ ...b, proxyId: proxy.id });
    }
  }
  // 新签发链（切换签发的目标）也必须完整且未停用。
  const newIssuerLeaf = { id: '(new-issuance-chain)', intermediateId: newIntermediateId };
  for (const b of chainBlockersForLeaf(newIssuerLeaf, intermediates, roots)) {
    blockers.push({ ...b, phase: PHASE_SWITCH });
  }

  const structuralBlockers = blockers.filter((b) => b.type !== 'proxy-nack');

  // ---- 阶段 1+2：按波次分发新根并收集 ACK ----
  const rounds = [];
  const maxWave = proxies.reduce((m, p) => Math.max(m, p.wave), 0);
  let rolledBack = false;
  let nackBlocker = null;

  const snapshot = (round, phase) => ({
    round,
    time: now + round * roundMs,
    phase,
    proxies: proxies.map((p) => ({
      id: p.id,
      service: p.service,
      wave: p.wave,
      trustBundle: [...p.trustBundle],
      ackedNewRoot: p.ackedNew,
      nackedNewRoot: p.nackedNew,
    })),
    riskyEdges: computeRiskyEdges(dependencies, proxiesByService, leafByProxy, intermediates),
  });

  rounds.push(snapshot(0, PHASE_DISTRIBUTE));

  for (let round = 1; round <= maxWave; round += 1) {
    for (const proxy of proxies) {
      if (proxy.wave === round && !proxy.trustBundle.includes(newRootId)) {
        proxy.trustBundle.push(newRootId);
      }
      if (proxy.trustBundle.includes(newRootId) && proxy.ack[newRootId] === true) {
        proxy.ackedNew = true;
      }
    }
    rounds.push(snapshot(round, PHASE_DISTRIBUTE));

    const nacked = proxies.filter((p) => p.nackedNew && p.trustBundle.includes(newRootId));
    if (nacked.length > 0) {
      nackBlocker = {
        type: 'proxy-nack',
        proxyIds: nacked.map((p) => p.id),
        message: `代理 ${nacked.map((p) => p.id).join(', ')} NACK 了新根 ${newRootId}`,
      };
      if (rollbackOnNack) {
        // 回滚：把新根从所有信任包中移除，恢复旧根单信任。
        for (const proxy of proxies) {
          proxy.trustBundle = proxy.trustBundle.filter((r) => r !== newRootId);
          proxy.ackedNew = false;
        }
        rounds.push(snapshot(round + 1, 'rollback'));
        rolledBack = true;
      }
      break;
    }
  }

  const dualTrustComplete =
    !rolledBack &&
    proxies.length > 0 &&
    proxies.every(
      (p) =>
        p.trustBundle.includes(oldRootId) && p.trustBundle.includes(newRootId) && p.ackedNew
    );

  // ---- 阶段 3：签发切换 ----
  const switchBlockers = [...structuralBlockers];
  if (nackBlocker) switchBlockers.push(nackBlocker);
  if (!dualTrustComplete && !rolledBack && !nackBlocker) {
    const pending = proxies.filter((p) => !p.ackedNew).map((p) => p.id);
    if (pending.length > 0) {
      switchBlockers.push({
        type: 'partial-ack',
        proxyIds: pending,
        message: `代理 ${pending.join(', ')} 尚未 ACK 新根，双信任未收敛`,
      });
    }
  }
  const switchDone = dualTrustComplete && switchBlockers.length === 0;
  const switchTime = switchDone ? now + maxWave * roundMs : null;

  // ---- 阶段 4：旧根退役 ----
  // 只要任一调用方向尚未同时具备新旧信任，或任一旧根叶证书仍在有效期内，就不能退役。
  const oldRootLeaves = leaves.filter((l) => rootOfLeaf(l, intermediates) === oldRootId);
  const lastOldLeafExpiry = oldRootLeaves.reduce(
    (m, l) => Math.max(m, l.notAfter ?? Number.POSITIVE_INFINITY),
    0
  );
  const retireBlockers = [...switchBlockers];
  if (!dualTrustComplete && !rolledBack) {
    retireBlockers.push({
      type: 'dual-trust-incomplete',
      message: '存在调用方向尚未同时具备新旧信任，禁止退役旧根',
    });
  }
  const retireDone = switchDone && retireBlockers.length === 0;
  const safeRetirementTime = retireDone ? Math.max(lastOldLeafExpiry, switchTime ?? 0) : null;

  const phases = [
    {
      name: PHASE_DISTRIBUTE,
      status: rolledBack ? 'rolled-back' : nackBlocker ? 'blocked' : 'done',
      blockers: nackBlocker ? [nackBlocker] : [],
    },
    {
      name: PHASE_DUAL_TRUST,
      status: rolledBack ? 'rolled-back' : dualTrustComplete ? 'done' : 'blocked',
      blockers: dualTrustComplete || rolledBack ? [] : switchBlockers,
    },
    {
      name: PHASE_SWITCH,
      status: rolledBack ? 'rolled-back' : switchDone ? 'done' : 'blocked',
      blockers: rolledBack ? [] : switchBlockers,
      switchTime,
    },
    {
      name: PHASE_RETIRE,
      status: rolledBack ? 'rolled-back' : retireDone ? 'ready' : 'blocked',
      blockers: rolledBack ? [] : retireBlockers,
      safeRetirementTime,
    },
  ];

  const finalRiskyEdges = computeRiskyEdges(
    dependencies,
    proxiesByService,
    leafByProxy,
    intermediates
  );

  return {
    status: rolledBack ? 'rolled-back' : retireDone ? 'planned' : 'blocked',
    phases,
    rounds,
    riskyEdges: finalRiskyEdges,
    safeRetirementTime,
    blockers: rolledBack ? [] : [...structuralBlockers, ...(nackBlocker ? [nackBlocker] : [])],
  };
}

module.exports = {
  planRotation,
  computeRiskyEdges,
  PHASE_DISTRIBUTE,
  PHASE_DUAL_TRUST,
  PHASE_SWITCH,
  PHASE_RETIRE,
};
