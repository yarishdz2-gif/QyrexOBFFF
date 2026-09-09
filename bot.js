'use strict';
/**
 * QyrexOBF Discord Bot — nivel MAX
 *
 * Env:
 *   DISCORD_TOKEN=...
 *   CLIENT_ID=...          (optional, for slash command register)
 *   ANTI_TAMPER=true|false (default true)
 *
 * Usage in Discord:
 *   /obf  + attach .lua file
 *   or:  !obf  + attach file
 *   or:  !obf ```lua ... ```
 *
 * Replies with obfuscated .lua when done (no HTTP timeout issues).
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const {
  Client, GatewayIntentBits, AttachmentBuilder,
  REST, Routes, SlashCommandBuilder
} = require('discord.js');

const {
  findLua, getRoot, buildAntiTamper,
  runPrometheus, runHercules, runIB2
} = require('./obfuscate');

const TOKEN = process.env.DISCORD_TOKEN || '';
const CLIENT_ID = process.env.CLIENT_ID || '';
const ANTI = String(process.env.ANTI_TAMPER || 'true').toLowerCase() !== 'false';

if (!TOKEN) {
  console.error('Set DISCORD_TOKEN');
  process.exit(1);
}

function runMax(source, onLog) {
  const log = (m) => { try { onLog && onLog(m); } catch (_) {} console.log('[obf]', m); };
  const steps = [];
  let code = source;

  if (!findLua()) throw new Error('lua5.1 no encontrado (usa Docker)');
  log('lua OK');
  getRoot();
  log('engines OK');

  if (ANTI) {
    log('AntiTamper…');
    try {
      code = buildAntiTamper() + '\n' + source;
      steps.push('AntiTamper:v2');
    } catch (_) {
      code = source;
      steps.push('AntiTamper:skip');
    }
  }

  log('Prometheus Strong…');
  try {
    code = runPrometheus(code, 'Strong');
    steps.push('Prometheus:Strong');
  } catch (e1) {
    log('Strong fail → Medium');
    try {
      code = runPrometheus(code, 'Medium');
      steps.push('Prometheus:Medium');
    } catch (e2) {
      code = runPrometheus(source, 'Medium');
      steps.push('Prometheus:Medium:clean');
    }
  }
  log('Prometheus OK · ' + code.length + ' B');

  log('Hercules…');
  try {
    code = runHercules(code);
    steps.push('Hercules');
  } catch (_) {
    steps.push('Hercules:skip');
  }

  log('IronBrew2…');
  try {
    code = runIB2(code);
    steps.push('IronBrew2');
  } catch (_) {
    steps.push('IronBrew2:skip');
  }

  if (!code || !code.length) throw new Error('Sin output');
  const header = '--QyrexObf [qyrex.hopto.org]\n';
  if (!code.startsWith('--QyrexObf')) code = header + code;
  return { code, steps };
}

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.DirectMessages
  ]
});

const busy = new Set();

async function extractSource(message, interaction) {
  // attachment
  const atts = interaction
    ? interaction.options.getAttachment('file')
    : (message && message.attachments && message.attachments.first());

  if (atts) {
    const url = atts.url || atts.attachment;
    const res = await fetch(url);
    const text = await res.text();
    if (text && text.trim().length > 2) return text;
  }

  // codeblock from message
  if (message && message.content) {
    const m = message.content.match(/```(?:lua|luau)?\s*([\s\S]*?)```/i);
    if (m && m[1] && m[1].trim().length > 2) return m[1];
    const stripped = message.content.replace(/^!obf\s*/i, '').trim();
    if (stripped.length > 20 && !stripped.startsWith('!')) return stripped;
  }
  return null;
}

async function handleObf(source, replyFn, statusFn) {
  const t0 = Date.now();
  await statusFn('⏳ **QyrexOBF MAX** iniciado…\nAntiTamper → Prometheus Strong → Hercules → IronBrew2');
  const { code, steps } = runMax(source, (line) => {
    // status updates are expensive; skip per-line on Discord
  });
  const ms = Date.now() - t0;
  const tmp = path.join(os.tmpdir(), 'qyrex-' + crypto.randomBytes(6).toString('hex') + '.lua');
  fs.writeFileSync(tmp, code, 'utf8');
  const file = new AttachmentBuilder(tmp, { name: 'qyrexobf-max.lua' });
  await replyFn({
    content: `✅ **MAX listo** en ${Math.round(ms / 1000)}s\n\`${steps.join(' → ')}\`\n${source.length} → ${code.length} bytes`,
    files: [file]
  });
  try { fs.unlinkSync(tmp); } catch (_) {}
}

client.once('ready', async () => {
  console.log('QyrexOBF bot ready as', client.user.tag);
  try { getRoot(); console.log('engines warm'); } catch (e) { console.error(e.message); }

  if (CLIENT_ID) {
    try {
      const rest = new REST({ version: '10' }).setToken(TOKEN);
      await rest.put(Routes.applicationCommands(CLIENT_ID), {
        body: [
          new SlashCommandBuilder()
            .setName('obf')
            .setDescription('Ofuscar Lua/Luau con QyrexOBF MAX')
            .addAttachmentOption(o =>
              o.setName('file').setDescription('.lua source').setRequired(true)
            )
            .toJSON()
        ]
      });
      console.log('slash /obf registered');
    } catch (e) {
      console.error('slash register failed', e.message);
    }
  }
});

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand() || interaction.commandName !== 'obf') return;
  const uid = interaction.user.id;
  if (busy.has(uid)) {
    return interaction.reply({ content: 'Ya tienes una ofuscación en curso.', ephemeral: true });
  }
  const source = await extractSource(null, interaction);
  if (!source) {
    return interaction.reply({ content: 'Adjunta un archivo .lua', ephemeral: true });
  }
  busy.add(uid);
  await interaction.deferReply();
  try {
    await handleObf(
      source,
      (payload) => interaction.editReply(payload),
      (text) => interaction.editReply(text)
    );
  } catch (e) {
    await interaction.editReply('❌ ' + String(e.message || e).slice(0, 500));
  } finally {
    busy.delete(uid);
  }
});

client.on('messageCreate', async (message) => {
  if (message.author.bot) return;
  if (!message.content || !/^!obf\b/i.test(message.content)) return;
  const uid = message.author.id;
  if (busy.has(uid)) {
    return message.reply('Ya tienes una ofuscación en curso.');
  }
  const source = await extractSource(message, null);
  if (!source) {
    return message.reply('Usa `!obf` con un archivo .lua adjunto o un bloque ```lua```');
  }
  busy.add(uid);
  const statusMsg = await message.reply('⏳ **QyrexOBF MAX** iniciado…');
  try {
    await handleObf(
      source,
      async (payload) => {
        await statusMsg.edit({ content: payload.content, files: payload.files || [] });
      },
      async (text) => { await statusMsg.edit(text); }
    );
  } catch (e) {
    await statusMsg.edit('❌ ' + String(e.message || e).slice(0, 500));
  } finally {
    busy.delete(uid);
  }
});

client.login(TOKEN);
