require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../frontend')));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const JWT_SECRET = process.env.JWT_SECRET || 'mym_secret_2025';
const CLAUDE_API_KEY = process.env.ANTHROPIC_API_KEY;

// ── Middleware авторизации ──────────────────────────────────
function authMiddleware(roles = []) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Нет токена' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (roles.length && !roles.includes(decoded.role)) return res.status(403).json({ error: 'Нет доступа' });
      req.user = decoded;
      next();
    } catch { res.status(401).json({ error: 'Токен недействителен' }); }
  };
}

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════

// Логин администратора
app.post('/api/auth/admin', async (req, res) => {
  const { login, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM admin WHERE login = $1', [login]);
  if (!rows.length) return res.status(401).json({ error: 'Неверный логин или пароль' });
  const ok = await bcrypt.compare(password, rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'Неверный логин или пароль' });
  const token = jwt.sign({ id: rows[0].id, role: 'admin', login }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, role: 'admin' });
});

// Логин рекрутера
app.post('/api/auth/recruiter', async (req, res) => {
  const { login, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM recruiters WHERE login = $1 AND is_active = true', [login]);
  if (!rows.length) return res.status(401).json({ error: 'Неверный логин или пароль' });
  const ok = await bcrypt.compare(password, rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'Неверный логин или пароль' });
  const token = jwt.sign({ id: rows[0].id, role: 'recruiter', name: rows[0].name }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, role: 'recruiter', name: rows[0].name });
});

// ══════════════════════════════════════════════════════════════
// ADMIN — Рекрутеры
// ══════════════════════════════════════════════════════════════
app.get('/api/admin/recruiters', authMiddleware(['admin']), async (req, res) => {
  const { rows } = await pool.query('SELECT id, name, login, is_active, created_at FROM recruiters ORDER BY created_at DESC');
  res.json(rows);
});

app.post('/api/admin/recruiters', authMiddleware(['admin']), async (req, res) => {
  const { name, login, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    'INSERT INTO recruiters (name, login, password_hash) VALUES ($1, $2, $3) RETURNING id, name, login',
    [name, login, hash]
  );
  res.json(rows[0]);
});

app.delete('/api/admin/recruiters/:id', authMiddleware(['admin']), async (req, res) => {
  await pool.query('UPDATE recruiters SET is_active = false WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

app.put('/api/admin/recruiters/:id/password', authMiddleware(['admin']), async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  await pool.query('UPDATE recruiters SET password_hash = $1 WHERE id = $2', [hash, req.params.id]);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
// ADMIN — Должности
// ══════════════════════════════════════════════════════════════
app.get('/api/positions', authMiddleware(['admin','recruiter']), async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM positions WHERE is_active = true ORDER BY name');
  res.json(rows);
});

app.post('/api/admin/positions', authMiddleware(['admin']), async (req, res) => {
  const { name, description, timer_minutes } = req.body;
  const { rows } = await pool.query(
    'INSERT INTO positions (name, description, timer_minutes) VALUES ($1, $2, $3) RETURNING *',
    [name, description, timer_minutes || 60]
  );
  res.json(rows[0]);
});

// ══════════════════════════════════════════════════════════════
// ADMIN — Аналитика
// ══════════════════════════════════════════════════════════════
app.get('/api/admin/analytics', authMiddleware(['admin']), async (req, res) => {
  const total = await pool.query('SELECT COUNT(*) FROM invitations');
  const completed = await pool.query("SELECT COUNT(*) FROM invitations WHERE status = 'completed'");
  const avgTest = await pool.query('SELECT ROUND(AVG(test_pct)) as avg FROM test_results');
  const byVerdict = await pool.query("SELECT recommendation, COUNT(*) FROM test_results GROUP BY recommendation");
  const byPosition = await pool.query(`
    SELECT p.name, COUNT(i.id) as total, ROUND(AVG(r.test_pct)) as avg_pct
    FROM positions p
    LEFT JOIN invitations i ON i.position_id = p.id
    LEFT JOIN test_results r ON r.invitation_id = i.id
    GROUP BY p.name ORDER BY total DESC
  `);
  const hardQ = await pool.query(`
    SELECT question_text, COUNT(*) as total, SUM(CASE WHEN is_correct = false THEN 1 ELSE 0 END) as wrong
    FROM test_answers GROUP BY question_text
    HAVING COUNT(*) > 0
    ORDER BY (SUM(CASE WHEN is_correct = false THEN 1 ELSE 0 END)::float / COUNT(*)) DESC
    LIMIT 5
  `);
  const monthly = await pool.query(`
    SELECT TO_CHAR(created_at, 'YYYY-MM') as month, COUNT(*) as count
    FROM test_results GROUP BY month ORDER BY month DESC LIMIT 6
  `);
  res.json({
    total: parseInt(total.rows[0].count),
    completed: parseInt(completed.rows[0].count),
    avg_test_pct: parseInt(avgTest.rows[0].avg) || 0,
    by_verdict: byVerdict.rows,
    by_position: byPosition.rows,
    hard_questions: hardQ.rows,
    monthly: monthly.rows
  });
});

// ══════════════════════════════════════════════════════════════
// RECRUITER — Приглашения
// ══════════════════════════════════════════════════════════════
app.post('/api/recruiter/invitations', authMiddleware(['recruiter']), async (req, res) => {
  const { position_id } = req.body;
  const token = uuidv4().replace(/-/g, '').slice(0, 24);
  const { rows } = await pool.query(
    'INSERT INTO invitations (token, recruiter_id, position_id) VALUES ($1, $2, $3) RETURNING *',
    [token, req.user.id, position_id]
  );
  res.json({ ...rows[0], url: `${req.protocol}://${req.get('host')}/test/${token}` });
});

app.get('/api/recruiter/candidates', authMiddleware(['recruiter']), async (req, res) => {
  const { rows } = await pool.query(`
    SELECT i.*, p.name as position_name, r.test_score, r.test_pct, r.case_score, r.recommendation, r.created_at as result_date
    FROM invitations i
    LEFT JOIN positions p ON p.id = i.position_id
    LEFT JOIN test_results r ON r.invitation_id = i.id
    WHERE i.recruiter_id = $1
    ORDER BY i.created_at DESC
  `, [req.user.id]);
  res.json(rows);
});

// ══════════════════════════════════════════════════════════════
// ADMIN — Все кандидаты
// ══════════════════════════════════════════════════════════════
app.get('/api/admin/candidates', authMiddleware(['admin']), async (req, res) => {
  const { rows } = await pool.query(`
    SELECT i.*, p.name as position_name, rec.name as recruiter_name,
           r.test_score, r.test_total, r.test_pct, r.case_score, r.recommendation, r.created_at as result_date
    FROM invitations i
    LEFT JOIN positions p ON p.id = i.position_id
    LEFT JOIN recruiters rec ON rec.id = i.recruiter_id
    LEFT JOIN test_results r ON r.invitation_id = i.id
    ORDER BY i.created_at DESC
  `);
  res.json(rows);
});

// Детальные ответы кандидата
app.get('/api/candidates/:invitationId/detail', authMiddleware(['admin','recruiter']), async (req, res) => {
  const { rows: inv } = await pool.query('SELECT * FROM invitations WHERE id = $1', [req.params.invitationId]);
  if (!inv.length) return res.status(404).json({ error: 'Не найдено' });
  if (req.user.role === 'recruiter' && inv[0].recruiter_id !== req.user.id) return res.status(403).json({ error: 'Нет доступа' });
  const { rows: result } = await pool.query('SELECT * FROM test_results WHERE invitation_id = $1', [req.params.invitationId]);
  const { rows: answers } = await pool.query('SELECT * FROM test_answers WHERE result_id = $1 ORDER BY id', [result[0]?.id]);
  res.json({ invitation: inv[0], result: result[0], answers });
});

// ══════════════════════════════════════════════════════════════
// CANDIDATE — Тест по токену
// ══════════════════════════════════════════════════════════════
app.get('/api/test/:token', async (req, res) => {
  const { rows } = await pool.query(`
    SELECT i.*, p.name as position_name, p.timer_minutes, p.id as pos_id
    FROM invitations i JOIN positions p ON p.id = i.position_id
    WHERE i.token = $1
  `, [req.params.token]);
  if (!rows.length) return res.status(404).json({ error: 'Ссылка недействительна' });
  if (rows[0].status === 'completed') return res.status(410).json({ error: 'Тест уже пройден. Ссылка одноразовая.' });
  res.json({ invitation: rows[0] });
});

// Получить вопросы
app.get('/api/test/:token/questions', async (req, res) => {
  const { rows: inv } = await pool.query('SELECT * FROM invitations WHERE token = $1', [req.params.token]);
  if (!inv.length || inv[0].status === 'completed') return res.status(404).json({ error: 'Недействительна' });
  const { rows } = await pool.query(
    'SELECT * FROM questions WHERE position_id = $1 ORDER BY sort_order',
    [inv[0].position_id]
  );
  res.json(rows);
});

// Получить кейсы
app.get('/api/test/:token/cases', async (req, res) => {
  const { rows: inv } = await pool.query('SELECT * FROM invitations WHERE token = $1', [req.params.token]);
  if (!inv.length) return res.status(404).json({ error: 'Недействительна' });
  const { rows } = await pool.query(
    'SELECT * FROM cases WHERE position_id = $1 ORDER BY sort_order',
    [inv[0].position_id]
  );
  res.json(rows);
});

// Начать тест (зафиксировать ФИО и телефон)
app.post('/api/test/:token/start', async (req, res) => {
  const { name, phone } = req.body;
  const { rows } = await pool.query(
    "UPDATE invitations SET candidate_name=$1, candidate_phone=$2, status='in_progress', started_at=NOW() WHERE token=$3 AND status='invited' RETURNING *",
    [name, phone, req.params.token]
  );
  if (!rows.length) return res.status(400).json({ error: 'Не удалось начать тест' });
  res.json({ ok: true });
});

// Чат с ИИ для кейсов
app.post('/api/test/:token/chat', async (req, res) => {
  const { rows: inv } = await pool.query('SELECT * FROM invitations WHERE token = $1', [req.params.token]);
  if (!inv.length) return res.status(404).json({ error: 'Недействительна' });

  const SYSTEM = `Ты — профессиональный HR-эксперт MYM Transform (Узбекистан). Ты оцениваешь ответы кандидата на практические задачи и кейсы по кадровому делопроизводству.

ПРАВИЛА:
- После каждого ответа кандидата кратко оцени его (1-2 предложения)
- Если ответ неполный — задай один уточняющий вопрос
- Если ответ полный — скажи "Хорошо, переходим к следующему заданию"
- Все комментарии строго по законодательству Узбекистана (ТК РУз №ЗРУ-798, ПКМ №971, ПКМ №891 от 27.12.2024, Закон №ЗРУ-547)
- Не давай правильный ответ во время интервью

Когда все задания пройдены, выдай заключение в формате:
===ИТОГ===
ПРАКТИЧЕСКИЕ ЗАДАЧИ: [X]/5
УПРАВЛЕНЧЕСКИЕ КЕЙСЫ: [X]/5
ОБЩАЯ ОЦЕНКА КЕЙСОВ: [X]/10
РЕКОМЕНДАЦИЯ: [ПРИНЯТЬ / НА РАССМОТРЕНИЕ / ОТКАЗАТЬ]
КОММЕНТАРИЙ:
[2-3 предложения]
===КОНЕЦ===`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': CLAUDE_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1000,
        system: SYSTEM,
        messages: req.body.messages
      })
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка ИИ: ' + err.message });
  }
});

// Сохранить результат
app.post('/api/test/:token/complete', async (req, res) => {
  const { testAnswers, testScore, testTotal, testPct, caseScore, recommendation, aiComment, casesTranscript } = req.body;
  const { rows: inv } = await pool.query('SELECT * FROM invitations WHERE token = $1', [req.params.token]);
  if (!inv.length) return res.status(404).json({ error: 'Недействительна' });

  const { rows: result } = await pool.query(
    `INSERT INTO test_results (invitation_id, test_score, test_total, test_pct, case_score, recommendation, ai_comment, cases_transcript)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
    [inv[0].id, testScore, testTotal, testPct, caseScore, recommendation, aiComment, casesTranscript]
  );

  if (testAnswers?.length) {
    for (const a of testAnswers) {
      await pool.query(
        `INSERT INTO test_answers (result_id, question_text, block_name, chosen_index, correct_index, is_correct, opt_a, opt_b, opt_c, opt_d)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [result[0].id, a.q, a.block, a.chosen, a.correct, a.isCorrect, a.opts[0], a.opts[1], a.opts[2], a.opts[3]]
      );
    }
  }

  await pool.query("UPDATE invitations SET status='completed', completed_at=NOW() WHERE token=$1", [req.params.token]);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
// Catch-all — отдаём frontend
// ══════════════════════════════════════════════════════════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MYM Transform HR Platform running on port ${PORT}`));
