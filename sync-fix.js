const db = require('./src/services/database');
const deploy = require('./src/services/deploy');
const { NodeSSH } = require('node-ssh');
const { decrypt } = require('./src/utils/crypto');

async function main() {
  console.log('正在初始化数据库...');
  if (typeof db.getDb === 'function') db.getDb();
  
  // 1. 全局禁用审计，确保环境纯净
  db.setSetting('audit_block_enabled', 'false');
  console.log('--- 已全局禁用审计规则 ---');

  const nodes = db.getAllNodes(false);
  console.log(`发现总节点数: ${nodes.length}，准备开始全量【深度重置同步】...`);
  
  let success = 0, failed = 0;
  for (const node of nodes) {
    console.log(`\n[${node.name}] (${node.host}) 正在重置...`);
    const ssh = new NodeSSH();
    try {
      // 获取 SSH 凭据
      const connectOpts = {
        host: node.ssh_host || node.host,
        port: node.ssh_port || 22,
        username: node.ssh_user || 'root',
        readyTimeout: 15000
      };
      if (node.ssh_key_path) connectOpts.privateKeyPath = node.ssh_key_path;
      else if (node.ssh_password) connectOpts.password = decrypt(node.ssh_password);

      await ssh.connect(connectOpts);
      
      // 深度清理
      console.log(`  -> 正在强制停止旧服务并清理残留进程...`);
      await ssh.execCommand('systemctl stop xray vless-agent || true');
      await ssh.execCommand('pkill -9 xray || true');
      await ssh.execCommand('rm -f /usr/local/etc/xray/config.json');
      ssh.dispose();

      // 调用同步逻辑推送新配置并重新启动
      const ok = await deploy.syncNodeConfig(node, db);
      if (ok) {
        success++;
        db.updateNode(node.id, { is_active: 1, remark: '', last_check: deploy.toSqlUtc() });
        console.log(`  ✅ [${node.name}] 重置并激活成功`);
      } else {
        failed++;
        console.log(`  ❌ [${node.name}] 重试启动失败`);
      }
    } catch (e) {
      failed++;
      console.log(`  💥 [${node.name}] SSH 异常: ${e.message}`);
      try { ssh.dispose(); } catch {}
    }
  }
  
  console.log(`\n================================`);
  console.log(`深度重置完成！成功:${success} 失败:${failed}`);
  process.exit(0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
