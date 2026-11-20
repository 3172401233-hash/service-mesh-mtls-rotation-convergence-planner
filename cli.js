#!/usr/bin/env node
'use strict';

// 用法: node cli.js <input.json>
// 从 JSON 文件读取抽象证书元数据，输出轮换收敛规划（JSON）。

const fs = require('node:fs');
const { planRotation } = require('./src/planner');

function main() {
  const file = process.argv[2];
  if (!file) {
    console.error('用法: node cli.js <input.json>');
    process.exit(2);
  }
  const input = JSON.parse(fs.readFileSync(file, 'utf8'));
  const plan = planRotation(input);
  console.log(JSON.stringify(plan, null, 2));
  if (plan.status === 'blocked') process.exitCode = 1;
}

main();
