import express from 'express';
import {
  registerUser,
  verifyEmailToken,
  verifyEmailCode,
  resendVerificationEmail,
  loginUser,
  requireAuthenticatedUser,
  requireAdminUser,
  getProfessorRequests,
  moderateProfessorRequest,
  getAllUsersAdmin,
  updateUserStatusAdmin,
} from './authService.js';
import { inscribeStudentInEvent } from './eventsService.js';
import { checkRateLimit, getClientIp, isBotHoneypotTriggered } from './rateLimit.js';
import {
  ensurePostgresSchema,
  query,
  isConfiguredWithRealDatabase,
  inMemoryUsers,
} from '../lib/db.js';
import { getConfiguredEmailProvider } from './emailService.js';

const { Router } = express;

function resolveOrigin(req: express.Request): string | undefined {
  const rawProto = (req.headers['x-forwarded-proto'] as string) || req.protocol || 'https';
  const rawHost = (req.headers['x-forwarded-host'] as string) || req.get('host');
  const proto = rawProto.split(',')[0].trim();
  const host = typeof rawHost === 'string' ? rawHost.split(',')[0].trim() : '';
  if (host) {
    return `${proto}://${host}`;
  }
  return undefined;
}

export function createApiApp(): express.Express {
  const app = express();

  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  // Safe JSON body parser that cooperates with Vercel pre-parsed req.body
  app.use((req, res, next) => {
    if (req.body !== undefined) {
      if (typeof req.body === 'string') {
        try {
          req.body = req.body.trim() ? JSON.parse(req.body) : {};
        } catch {
          return res.status(400).json({ success: false, message: 'JSON inválido.' });
        }
      }
      return next();
    }
    express.json()(req, res, next);
  });

  const router = Router();

  // Healthcheck
  router.get('/health', async (_req, res) => {
    const emailProvider = getConfiguredEmailProvider();
    const runtime = process.env.VERCEL ? 'vercel_serverless' : 'node_server';

    if (!isConfiguredWithRealDatabase) {
      return res.status(200).json({
        status: 'online',
        runtime,
        database: 'preview_mode',
        target: 'Render PostgreSQL',
        email_provider: emailProvider,
        message:
          'Servidor ativo. Modo preview ativado. Ao configurar a DATABASE_URL real do Render na Vercel, o PostgreSQL conectará automaticamente.',
        total_usuarios: inMemoryUsers.length,
      });
    }

    try {
      await ensurePostgresSchema();
      const startTime = Date.now();
      const result = await query(
        'SELECT NOW() as current_time, count(*)::int as total_usuarios FROM usuario'
      );
      const latency = Date.now() - startTime;
      return res.status(200).json({
        status: 'online',
        runtime,
        database: 'connected',
        target: 'Render PostgreSQL',
        email_provider: emailProvider,
        latency: `${latency}ms`,
        server_time: result.rows[0]?.current_time,
        total_usuarios: result.rows[0]?.total_usuarios,
        database_url_configured: true,
      });
    } catch (err: any) {
      return res.status(503).json({
        status: 'warning',
        runtime,
        database: 'sleeping_or_unreachable',
        email_provider: emailProvider,
        error: err.message,
        code: err.code,
        database_url_configured: true,
        hint: 'O banco Render pode estar despertando (free-tier spin-down). Tente novamente em instantes.',
      });
    }
  });

  // Register (Student email verification or Professor admin request)
  router.post('/auth/register', async (req, res) => {
    const body = req.body || {};

    if (isBotHoneypotTriggered(body)) {
      return res.status(400).json({
        success: false,
        message: 'Solicitação rejeitada pela verificação anti-spam.',
      });
    }

    const ip = getClientIp(req);
    const ipRate = checkRateLimit(`register:ip:${ip}`, 10, 15 * 60 * 1000);
    if (!ipRate.allowed) {
      return res.status(429).json({
        success: false,
        message: `Muitas tentativas de cadastro. Aguarde ${ipRate.retryAfterSeconds} segundos.`,
      });
    }

    try {
      const result = await registerUser({
        nome: body.nome,
        email: body.email,
        senha: body.senha,
        perfil: body.perfil,
        matricula: body.matricula,
        telefone: body.telefone,
        materias: body.materias,
        ip,
        baseUrl: resolveOrigin(req),
      });
      return res.status(201).json(result);
    } catch (error: any) {
      const statusCode = error.statusCode || (error.code === '23505' ? 409 : 500);
      const message =
        error.code === '23505'
          ? 'Já existe um usuário cadastrado com estes dados (e-mail ou matrícula já em uso).'
          : error.message || 'Erro ao gravar usuário no banco de dados.';
      return res.status(statusCode).json({
        success: false,
        message,
        errorCode: error.errorCode || error.code || 'DB_ERROR',
      });
    }
  });

  // Login
  router.post('/auth/login', async (req, res) => {
    const ip = getClientIp(req);
    const ipRate = checkRateLimit(`login:ip:${ip}`, 25, 5 * 60 * 1000);
    if (!ipRate.allowed) {
      return res.status(429).json({
        success: false,
        message: `Muitas tentativas de login. Aguarde ${ipRate.retryAfterSeconds} segundos.`,
      });
    }

    try {
      const { email, senha, isDemoQuickLogin } = req.body || {};
      const result = await loginUser({ email, senha, isDemoQuickLogin: Boolean(isDemoQuickLogin) });
      return res.status(200).json(result);
    } catch (error: any) {
      return res.status(error.statusCode || 401).json({
        success: false,
        message: error.message || 'Erro ao realizar login.',
        errorCode: error.errorCode || 'AUTH_ERROR',
        email: error.email,
      });
    }
  });

  // Verify student email (link token OR 6-digit OTP code + email)
  router.all('/auth/verify-email', async (req, res) => {
    if (!['GET', 'POST'].includes(req.method)) {
      return res.status(405).json({ success: false, message: 'Método não permitido.' });
    }
    const ip = getClientIp(req);
    const ipRate = checkRateLimit(`verify:ip:${ip}`, 30, 15 * 60 * 1000);
    if (!ipRate.allowed) {
      return res.status(429).json({
        success: false,
        message: 'Muitas tentativas de verificação. Tente novamente em alguns minutos.',
      });
    }

    const token = (req.query?.token as string) || req.body?.token || '';
    const email = req.body?.email || '';
    const code = req.body?.code || '';

    try {
      const result =
        email && code
          ? await verifyEmailCode({ email, code })
          : await verifyEmailToken(token);
      return res.status(200).json(result);
    } catch (error: any) {
      return res.status(error.statusCode || 400).json({
        success: false,
        message: error.message || 'Não foi possível verificar o e-mail.',
        errorCode: error.errorCode || 'VERIFY_ERROR',
      });
    }
  });

  // Resend verification email
  router.post('/auth/resend-verification', async (req, res) => {
    const body = req.body || {};
    if (isBotHoneypotTriggered(body)) {
      return res.status(400).json({ success: false, message: 'Requisição inválida.' });
    }
    const ip = getClientIp(req);
    const ipRate = checkRateLimit(`resend:ip:${ip}`, 10, 15 * 60 * 1000);
    if (!ipRate.allowed) {
      return res.status(429).json({
        success: false,
        message: `Muitas solicitações de reenvio. Aguarde ${ipRate.retryAfterSeconds} segundos.`,
      });
    }

    try {
      const result = await resendVerificationEmail({
        email: body.email || '',
        ip,
        baseUrl: resolveOrigin(req),
      });
      return res.status(200).json(result);
    } catch (error: any) {
      return res.status(error.statusCode || 400).json({
        success: false,
        message: error.message || 'Erro ao reenviar e-mail de verificação.',
        errorCode: error.errorCode || 'RESEND_ERROR',
        retryAfterSeconds: error.retryAfterSeconds,
      });
    }
  });

  // Current authenticated user
  router.get('/auth/me', async (req, res) => {
    try {
      const user = await requireAuthenticatedUser(req);
      return res.status(200).json({ success: true, user });
    } catch (error: any) {
      return res.status(error.statusCode || 401).json({
        success: false,
        message: error.message || 'Sessão inválida.',
        errorCode: error.errorCode || 'UNAUTHORIZED',
      });
    }
  });

  // Admin: Exclusive Professor Requests list
  router.get('/admin/professors', async (req, res) => {
    try {
      await requireAdminUser(req);
      const professors = await getProfessorRequests();
      return res.status(200).json({ success: true, professors });
    } catch (error: any) {
      return res.status(error.statusCode || 403).json({
        success: false,
        message: error.message || 'Erro ao carregar solicitações de professores.',
        errorCode: error.errorCode || 'ADMIN_REQUIRED',
      });
    }
  });

  // Admin: Approve or Reject Professor Request
  router.all('/admin/professors/:id/decision', async (req, res) => {
    if (!['PATCH', 'POST'].includes(req.method)) {
      return res.status(405).json({ success: false, message: 'Método não permitido.' });
    }
    try {
      const admin = await requireAdminUser(req);
      const professorId = parseInt(req.params.id, 10);
      if (Number.isNaN(professorId)) {
        return res.status(400).json({ success: false, message: 'ID do professor inválido.' });
      }
      const { decision, motivo } = req.body || {};
      const professor = await moderateProfessorRequest({
        professorId,
        adminId: admin.id_usuario,
        decision,
        motivo,
      });
      return res.status(200).json({ success: true, professor });
    } catch (error: any) {
      return res.status(error.statusCode || 400).json({
        success: false,
        message: error.message || 'Erro ao registrar decisão administrativa.',
        errorCode: error.errorCode || 'ADMIN_ERROR',
      });
    }
  });

  // Admin: General User Directory & Status Governance
  router.get('/admin/users', async (req, res) => {
    try {
      await requireAdminUser(req);
      const users = await getAllUsersAdmin();
      return res.status(200).json({ success: true, users });
    } catch (error: any) {
      return res.status(error.statusCode || 403).json({
        success: false,
        message: error.message || 'Erro ao carregar usuários.',
      });
    }
  });

  router.patch('/admin/users', async (req, res) => {
    try {
      const admin = await requireAdminUser(req);
      const { userId, status, motivo } = req.body || {};
      const user = await updateUserStatusAdmin({
        userId: Number(userId),
        adminId: admin.id_usuario,
        status,
        motivo,
      });
      return res.status(200).json({ success: true, user });
    } catch (error: any) {
      return res.status(error.statusCode || 400).json({
        success: false,
        message: error.message || 'Erro ao atualizar status da conta.',
      });
    }
  });

  // Protected Event Inscription endpoint
  router.post('/events/:id/inscribe', async (req, res) => {
    try {
      const user = await requireAuthenticatedUser(req);
      const eventoId = parseInt(req.params.id, 10);
      const result = await inscribeStudentInEvent({ user, eventoId });
      return res.status(201).json(result);
    } catch (error: any) {
      return res.status(error.statusCode || 403).json({
        success: false,
        message: error.message || 'Erro ao realizar inscrição no evento.',
        errorCode: error.errorCode || 'INSCRIPTION_ERROR',
      });
    }
  });

  // Protected Event Creation endpoint
  router.post('/events', async (req, res) => {
    try {
      const user = await requireAuthenticatedUser(req);
      if (!['PROFESSOR', 'ADMINISTRADOR'].includes(user.perfil)) {
        return res.status(403).json({
          success: false,
          message: 'Apenas professores aprovados ou administradores podem criar eventos.',
          errorCode: 'PROFESSOR_REQUIRED',
        });
      }
      return res.status(201).json({ success: true, organizerId: user.id_usuario });
    } catch (error: any) {
      return res.status(error.statusCode || 403).json({
        success: false,
        message: error.message || 'Erro ao autorizar criação de evento.',
        errorCode: error.errorCode || 'AUTH_ERROR',
      });
    }
  });

  app.use('/api', router);

  app.use('/api', (_req, res) => {
    res.status(404).json({ success: false, message: 'Rota da API não encontrada.' });
  });

  return app;
}
