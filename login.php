<?php
// ─── login.php ────────────────────────────────────────────────────────────────
session_start();

header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

define('DB_HOST', 'localhost');
define('DB_NAME', 'correia_quintella');
define('DB_USER', 'cq_user');
define('DB_PASS', 'sua_senha_segura');
define('WA_NUMBER', '5561999999999');

$ip = $_SERVER['REMOTE_ADDR'];
if (!isset($_SESSION['login_attempts'][$ip])) {
    $_SESSION['login_attempts'][$ip] = ['count' => 0, 'first_time' => time()];
}
$att = &$_SESSION['login_attempts'][$ip];
if (time() - $att['first_time'] > 900) {
    $att = ['count' => 0, 'first_time' => time()];
}
$blocked = $att['count'] >= 5;

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (!empty($_SESSION['user_id'])) {
    $role = $_SESSION['role'] ?? 'cliente';
    header('Location: ' . ($role === 'cliente' ? 'portal_cliente.php' : 'portal_admin.php'));
    exit;
}

function getDB() {
    static $pdo = null;
    if ($pdo === null) {
        try {
            $pdo = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4', DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (PDOException $e) {
            error_log('DB error: ' . $e->getMessage());
            return null;
        }
    }
    return $pdo;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        $error = 'Requisição inválida. Recarregue a página.';
    } elseif ($blocked) {
        $error = 'Muitas tentativas. Aguarde 15 min ou contate via WhatsApp.';
    } else {
        $usuario = trim($_POST['usuario'] ?? '');
        $senha   = $_POST['senha'] ?? '';
        if (empty($usuario) || empty($senha)) {
            $error = 'Preencha usuário e senha.';
        } else {
            $pdo = getDB();
            if (!$pdo) {
                $error = 'Erro interno. Tente novamente.';
            } else {
                $stmt = $pdo->prepare("SELECT id,nome,email,senha_hash,role,ativo FROM usuarios WHERE usuario=:u LIMIT 1");
                $stmt->execute([':u' => $usuario]);
                $user = $stmt->fetch();
                if ($user && $user['ativo'] && password_verify($senha, $user['senha_hash'])) {
                    $att['count'] = 0;
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['nome']    = $user['nome'];
                    $_SESSION['role']    = $user['role'];
                    $_SESSION['email']   = $user['email'];
                    if (!empty($_POST['lembrar'])) {
                        $token = bin2hex(random_bytes(32));
                        $s2 = $pdo->prepare("UPDATE usuarios SET remember_token=:tok WHERE id=:id");
                        $s2->execute([':tok' => hash('sha256', $token), ':id' => $user['id']]);
                        setcookie('remember_me', $token, ['expires'=>time()+86400*30,'path'=>'/','httponly'=>true,'samesite'=>'Strict','secure'=>isset($_SERVER['HTTPS'])]);
                    }
                    header('Location: ' . ($user['role']==='cliente' ? 'portal_cliente.php' : 'portal_admin.php'));
                    exit;
                } else {
                    $att['count']++;
                    $r = 5 - $att['count'];
                    $error = 'Usuário ou senha incorretos.' . ($r > 0 ? " Tentativas restantes: $r." : ' Conta temporariamente bloqueada.');
                }
            }
        }
    }
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Área do Cliente – Correia Quintella</title>
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700;900&family=Cormorant+Garamond:ital,wght@0,300;1,300&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet"/>
  <style>
    :root {
      --green:      #3a6b44;
      --green-dark: #2a4f33;
      --green-mid:  #1e3825;
      --green-deep: #162a1e;
      --gold:       #c9a84c;
      --gold-light: #e8c97a;
      --white:      #ffffff;
      --red:        #e07070;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    html, body {
      height: 100%;
      overflow: hidden;
    }

    body {
      font-family: 'DM Sans', sans-serif;
      display: flex;
      flex-direction: column;
      background: var(--green-deep);
    }

    /* BG */
    .bg {
      position: fixed; inset: 0; z-index: 0;
      background:
        radial-gradient(ellipse 70% 55% at 8% 15%, rgba(58,107,68,.5) 0%, transparent 55%),
        radial-gradient(ellipse 55% 65% at 92% 85%, rgba(201,168,76,.1) 0%, transparent 50%),
        linear-gradient(155deg, #1a3022 0%, #1e3825 45%, #162a1e 100%);
    }
    .bg::before {
      content:''; position:absolute; inset:0;
      background-image:
        repeating-linear-gradient(0deg,transparent,transparent 59px,rgba(255,255,255,.02) 60px),
        repeating-linear-gradient(90deg,transparent,transparent 59px,rgba(255,255,255,.02) 60px);
    }
    .bg::after {
      content:''; position:absolute; top:-60px; right:-60px;
      width:340px; height:340px; border-radius:50%;
      border:1px solid rgba(201,168,76,.08);
      box-shadow: 0 0 0 35px rgba(201,168,76,.03), 0 0 0 70px rgba(201,168,76,.015);
    }

    /* TOP BAR */
    .topbar {
      position:relative; z-index:10;
      padding: 12px 32px;
      display:flex; align-items:center; justify-content:space-between;
      border-bottom: 1px solid rgba(201,168,76,.1);
      flex-shrink: 0;
    }
    .topbar a {
      font-size:11px; letter-spacing:.14em; text-transform:uppercase;
      color:rgba(255,255,255,.45); text-decoration:none;
      display:flex; align-items:center; gap:7px; transition:color .2s;
    }
    .topbar a:hover { color:var(--gold-light); }
    .topbar-label { font-size:9px; letter-spacing:.22em; text-transform:uppercase; color:rgba(255,255,255,.18); }

    /* WRAPPER */
    .wrapper {
      position:relative; z-index:5;
      flex:1; display:flex; align-items:center; justify-content:center;
      padding: 12px 20px;
      min-height: 0;
    }

    /* CARD */
    .card {
      width:100%; max-width:420px;
      background: rgba(255,255,255,.04);
      border: 1px solid rgba(201,168,76,.18);
      border-radius: 20px;
      padding: 28px 36px 24px;
      backdrop-filter: blur(18px);
      box-shadow: 0 20px 60px rgba(0,0,0,.4), 0 1px 0 rgba(255,255,255,.05) inset;
    }

    /* LOGO */
    .logo { text-align:center; margin-bottom:18px; }
    .logo-img {
      height:54px; width:auto; object-fit:contain;
      filter:brightness(0) invert(1); margin-bottom:8px;
    }
    .brand { font-family:'Playfair Display',serif; font-size:17px; font-weight:700; color:#fff; letter-spacing:.04em; }
    .brand-sub { font-size:8px; letter-spacing:.24em; text-transform:uppercase; color:var(--gold-light); margin-top:2px; }
    .gold-line { width:40px; height:2px; background:linear-gradient(90deg,var(--gold),var(--gold-light)); margin:10px auto 0; border-radius:2px; }

    /* BADGE */
    .badge {
      display:flex; align-items:center; justify-content:center; gap:6px;
      background:rgba(201,168,76,.1); border:1px solid rgba(201,168,76,.22);
      border-radius:100px; padding:5px 13px; margin:0 auto 16px;
      font-size:9.5px; font-weight:500; letter-spacing:.14em; text-transform:uppercase;
      color:var(--gold-light); width:fit-content;
    }

    .title { font-family:'Playfair Display',serif; font-size:22px; font-weight:700; color:#fff; text-align:center; margin-bottom:3px; }
    .subtitle { font-family:'Cormorant Garamond',serif; font-size:13px; font-weight:300; font-style:italic; color:rgba(255,255,255,.45); text-align:center; margin-bottom:20px; }

    /* ALERT */
    .alert {
      border-radius:9px; padding:10px 14px; font-size:12.5px;
      margin-bottom:16px; display:flex; align-items:flex-start; gap:9px;
    }
    .alert.error { background:rgba(192,57,43,.12); border:1px solid rgba(192,57,43,.28); color:var(--red); }
    .alert svg { flex-shrink:0; margin-top:1px; }

    /* FORM */
    .form-group { margin-bottom:14px; }
    .form-label { display:block; font-size:9.5px; font-weight:500; letter-spacing:.2em; text-transform:uppercase; color:rgba(255,255,255,.45); margin-bottom:6px; }
    .form-input {
      width:100%; background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.1);
      border-radius:9px; padding:11px 14px; font-family:'DM Sans',sans-serif;
      font-size:14px; font-weight:300; color:#fff; outline:none;
      transition:border-color .25s, background .25s;
    }
    .form-input::placeholder { color:rgba(255,255,255,.26); }
    .form-input:focus { border-color:rgba(201,168,76,.5); background:rgba(255,255,255,.07); }

    .pw-wrap { position:relative; }
    .pw-wrap .form-input { padding-right:42px; }
    .toggle-pw {
      position:absolute; right:12px; top:50%; transform:translateY(-50%);
      background:none; border:none; cursor:pointer; padding:4px;
      color:rgba(255,255,255,.32); transition:color .2s;
    }
    .toggle-pw:hover { color:var(--gold-light); }

    .row {
      display:flex; align-items:center; justify-content:space-between;
      margin-bottom:20px; gap:10px;
    }
    .remember {
      display:flex; align-items:center; gap:7px; cursor:pointer;
      font-size:12px; font-weight:300; color:rgba(255,255,255,.5); user-select:none;
    }
    .remember input[type=checkbox] {
      appearance:none; -webkit-appearance:none; width:15px; height:15px;
      border:1px solid rgba(255,255,255,.2); border-radius:4px;
      background:rgba(255,255,255,.05); cursor:pointer; flex-shrink:0;
      position:relative; transition:border-color .2s, background .2s;
    }
    .remember input:checked { background:var(--gold); border-color:var(--gold); }
    .remember input:checked::after {
      content:''; position:absolute; left:4px; top:1px; width:5px; height:9px;
      border:2px solid var(--green-dark); border-top:none; border-left:none; transform:rotate(45deg);
    }
    .forgot { font-size:11.5px; color:var(--gold-light); text-decoration:none; white-space:nowrap; transition:opacity .2s; }
    .forgot:hover { opacity:.7; }

    .btn {
      width:100%; background:var(--gold); color:var(--green-dark); border:none;
      border-radius:9px; padding:13px; font-family:'DM Sans',sans-serif;
      font-size:12px; font-weight:500; letter-spacing:.16em; text-transform:uppercase;
      cursor:pointer; transition:background .25s, transform .2s, box-shadow .25s;
      box-shadow:0 4px 18px rgba(201,168,76,.28);
    }
    .btn:hover { background:var(--gold-light); transform:translateY(-1px); box-shadow:0 7px 26px rgba(201,168,76,.38); }
    .btn:disabled { opacity:.4; cursor:not-allowed; transform:none; }

    /* WA NOTE */
    .wa-note {
      margin-top:14px; padding:11px 13px;
      background:rgba(37,211,102,.06); border:1px solid rgba(37,211,102,.15);
      border-radius:9px; display:flex; align-items:flex-start; gap:10px;
      font-size:11.5px; font-weight:300; color:rgba(255,255,255,.45); line-height:1.5;
    }
    .wa-note svg { flex-shrink:0; margin-top:1px; color:#25d366; }
    .wa-note a { color:#25d366; text-decoration:none; font-weight:500; }
    .wa-note a:hover { text-decoration:underline; }

    /* DIVIDER */
    .divider { height:1px; background:rgba(255,255,255,.07); margin:16px 0; }

    /* CHIPS */
    .chips { display:flex; align-items:center; justify-content:center; gap:8px; flex-wrap:wrap; }
    .chip {
      display:flex; align-items:center; gap:5px;
      background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.08);
      border-radius:100px; padding:4px 11px;
      font-size:10px; color:rgba(255,255,255,.34); letter-spacing:.05em;
    }

    /* BLOCKED */
    .blocked { text-align:center; padding:8px 0; }
    .blocked p { font-size:13px; color:rgba(255,255,255,.5); margin-bottom:14px; line-height:1.6; }
    .wa-btn {
      display:inline-flex; align-items:center; gap:8px; background:#25d366;
      color:#fff; border-radius:8px; padding:11px 22px; text-decoration:none;
      font-size:13px; font-weight:500; transition:opacity .2s;
    }
    .wa-btn:hover { opacity:.88; }

    /* MOBILE */
    @media (max-width: 480px) {
      .card { padding:22px 20px 20px; border-radius:16px; }
      .topbar { padding:10px 16px; }
      .title { font-size:19px; }
      .logo-img { height:46px; }
    }

    @media (max-height: 660px) {
      .logo { margin-bottom:10px; }
      .logo-img { height:44px; }
      .badge { margin-bottom:10px; }
      .subtitle { margin-bottom:14px; }
      .form-group { margin-bottom:10px; }
      .card { padding:20px 32px 18px; }
    }
  </style>
</head>
<body>
<div class="bg"></div>

<div class="topbar">
  <a href="index.html">
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
    Voltar ao site
  </a>
  <span class="topbar-label">Área Restrita</span>
</div>

<div class="wrapper">
  <div class="card">

    <div class="logo">
      <img src="Logo_preto_jpg.jpeg" alt="Correia Quintella" class="logo-img">
      <div class="brand">Correia Quintella</div>
      <div class="brand-sub">Assessoria &amp; Consultoria de Cidadanias</div>
      <div class="gold-line"></div>
    </div>

    <div class="badge">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
      Área restrita para clientes
    </div>

    <div class="title">Acessar Conta</div>
    <div class="subtitle">Acompanhe seu processo de cidadania</div>

    <?php if ($error): ?>
    <div class="alert error">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
    </div>
    <?php endif; ?>

    <?php if ($blocked): ?>
    <div class="blocked">
      <p>Muitas tentativas de login.<br>Entre em contato pelo WhatsApp para recuperar o acesso.</p>
      <a href="https://wa.me/<?php echo WA_NUMBER; ?>?text=Olá!%20Preciso%20recuperar%20o%20acesso%20à%20minha%20conta%20no%20portal." target="_blank" class="wa-btn">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893A11.821 11.821 0 0020.885 3.49"/></svg>
        Falar com a equipe
      </a>
    </div>
    <?php else: ?>

    <form method="POST" action="login.php" autocomplete="off" novalidate>
      <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

      <div class="form-group">
        <label class="form-label" for="usuario">Usuário</label>
        <input class="form-input" type="text" id="usuario" name="usuario" placeholder="Digite seu usuário" autocomplete="username" maxlength="60" value="<?php echo htmlspecialchars($_POST['usuario'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
      </div>

      <div class="form-group">
        <label class="form-label" for="senha">Senha</label>
        <div class="pw-wrap">
          <input class="form-input" type="password" id="senha" name="senha" placeholder="Digite sua senha" autocomplete="current-password" maxlength="128" required>
          <button type="button" class="toggle-pw" aria-label="Mostrar/ocultar senha" id="togglePass">
            <svg id="eyeIcon" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
            </svg>
          </button>
        </div>
      </div>

      <div class="row">
        <label class="remember">
          <input type="checkbox" name="lembrar" value="1"> Lembrar senha
        </label>
        <a href="https://wa.me/<?php echo WA_NUMBER; ?>?text=Olá!%20Esqueci%20minha%20senha." target="_blank" class="forgot">Esqueceu a senha?</a>
      </div>

      <button type="submit" class="btn">Entrar</button>
    </form>

    <div class="wa-note">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893A11.821 11.821 0 0020.885 3.49"/></svg>
      <span>Recuperação de acesso feita pelo WhatsApp da nossa equipe. <a href="https://wa.me/<?php echo WA_NUMBER; ?>?text=Olá!%20Preciso%20recuperar%20minha%20senha%20do%20portal." target="_blank">Clique aqui.</a></span>
    </div>

    <?php endif; ?>

    <div class="divider"></div>

    <div class="chips">
      <div class="chip">👤 Cliente</div>
      <div class="chip">⚖️ Advogada</div>
      <div class="chip">📋 Secretaria</div>
    </div>

  </div>
</div>

<script>
const togglePass = document.getElementById('togglePass');
const senhaInput = document.getElementById('senha');
const eyeIcon    = document.getElementById('eyeIcon');
if (togglePass) {
  togglePass.addEventListener('click', () => {
    const isPass = senhaInput.type === 'password';
    senhaInput.type = isPass ? 'text' : 'password';
    eyeIcon.innerHTML = isPass
      ? `<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>`
      : `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
  });
}
const loginForm = document.querySelector('form');
if (loginForm) {
  loginForm.addEventListener('submit', function() {
    const btn = this.querySelector('.btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Entrando…'; }
  });
}
</script>
</body>
</html>