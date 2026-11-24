const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, '..', 'security.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS guild_settings (
    guild_id TEXT PRIMARY KEY,
    prefix TEXT DEFAULT '!',
    antinuke_punishment TEXT DEFAULT 'strip',
    antinuke_limit INTEGER DEFAULT 3,
    antispam_limit INTEGER DEFAULT 5,
    antispam_window_ms INTEGER DEFAULT 5000,
    alt_age_days INTEGER DEFAULT 7,
    block_invites INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS log_channels (
    guild_id TEXT PRIMARY KEY,
    security_channel TEXT,
    mod_channel TEXT,
    message_channel TEXT,
    member_channel TEXT,
    server_channel TEXT,
    vc_channel TEXT
  );

  CREATE TABLE IF NOT EXISTS whitelist (
    guild_id TEXT,
    target_id TEXT,
    type TEXT,
    PRIMARY KEY (guild_id, target_id)
  );

  CREATE TABLE IF NOT EXISTS log_ignores (
    guild_id TEXT,
    target_id TEXT,
    type TEXT,
    PRIMARY KEY (guild_id, target_id)
  );

  CREATE TABLE IF NOT EXISTS warnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id TEXT,
    user_id TEXT,
    moderator_id TEXT,
    reason TEXT,
    created_at INTEGER
  );
`);

function getSettings(guildId) {
  let row = db.prepare('SELECT * FROM guild_settings WHERE guild_id = ?').get(guildId);
  if (!row) {
    db.prepare('INSERT INTO guild_settings (guild_id) VALUES (?)').run(guildId);
    row = db.prepare('SELECT * FROM guild_settings WHERE guild_id = ?').get(guildId);
  }
  return row;
}

function updateSetting(guildId, key, value) {
  getSettings(guildId);
  const allowed = [
    'prefix',
    'antinuke_punishment',
    'antinuke_limit',
    'antispam_limit',
    'antispam_window_ms',
    'alt_age_days',
    'block_invites',
  ];
  if (!allowed.includes(key)) throw new Error(`Invalid setting key: ${key}`);
  db.prepare(`UPDATE guild_settings SET ${key} = ? WHERE guild_id = ?`).run(value, guildId);
}

function getLogChannels(guildId) {
  return db.prepare('SELECT * FROM log_channels WHERE guild_id = ?').get(guildId) || {};
}

function setLogChannels(guildId, channels) {
  db.prepare(`
    INSERT INTO log_channels (guild_id, security_channel, mod_channel, message_channel, member_channel, server_channel, vc_channel)
    VALUES (@guild_id, @security_channel, @mod_channel, @message_channel, @member_channel, @server_channel, @vc_channel)
    ON CONFLICT(guild_id) DO UPDATE SET
      security_channel = excluded.security_channel,
      mod_channel = excluded.mod_channel,
      message_channel = excluded.message_channel,
      member_channel = excluded.member_channel,
      server_channel = excluded.server_channel,
      vc_channel = excluded.vc_channel
  `).run({ guild_id: guildId, ...channels });
}

function isWhitelisted(guildId, targetIds) {
  const rows = db.prepare('SELECT target_id FROM whitelist WHERE guild_id = ?').all(guildId);
  const set = new Set(rows.map((r) => r.target_id));
  return targetIds.some((id) => set.has(id));
}

function toggleWhitelist(guildId, targetId, type) {
  const existing = db.prepare('SELECT 1 FROM whitelist WHERE guild_id = ? AND target_id = ?').get(guildId, targetId);
  if (existing) {
    db.prepare('DELETE FROM whitelist WHERE guild_id = ? AND target_id = ?').run(guildId, targetId);
    return false;
  }
  db.prepare('INSERT INTO whitelist (guild_id, target_id, type) VALUES (?, ?, ?)').run(guildId, targetId, type);
  return true;
}

function isLogIgnored(guildId, targetIds) {
  const rows = db.prepare('SELECT target_id FROM log_ignores WHERE guild_id = ?').all(guildId);
  const set = new Set(rows.map((r) => r.target_id));
  return targetIds.some((id) => set.has(id));
}

function toggleLogIgnore(guildId, targetId, type) {
  const existing = db.prepare('SELECT 1 FROM log_ignores WHERE guild_id = ? AND target_id = ?').get(guildId, targetId);
  if (existing) {
    db.prepare('DELETE FROM log_ignores WHERE guild_id = ? AND target_id = ?').run(guildId, targetId);
    return false;
  }
  db.prepare('INSERT INTO log_ignores (guild_id, target_id, type) VALUES (?, ?, ?)').run(guildId, targetId, type);
  return true;
}

function addWarning(guildId, userId, moderatorId, reason) {
  db.prepare('INSERT INTO warnings (guild_id, user_id, moderator_id, reason, created_at) VALUES (?, ?, ?, ?, ?)').run(
    guildId,
    userId,
    moderatorId,
    reason,
    Date.now()
  );
}

function getWarnings(guildId, userId) {
  return db
    .prepare('SELECT * FROM warnings WHERE guild_id = ? AND user_id = ? ORDER BY created_at DESC')
    .all(guildId, userId);
}

module.exports = {
  getSettings,
  updateSetting,
  getLogChannels,
  setLogChannels,
  isWhitelisted,
  toggleWhitelist,
  isLogIgnored,
  toggleLogIgnore,
  addWarning,
  getWarnings,
};
