<?php
session_start();
require 'vendor/autoload.php';
$PDO = new PDO('mysql:dbname=php_users;host=localhost;charset=utf8mb4', 'root', '');
$PDO->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
if (isset($_POST['EventofRegistration'])) {
    $name = trim($_POST['userName']);
    $password = $_POST['password'];
    $bg_color = $_POST['bg_color'] ?? '#ffffff';
    $text_color = $_POST['text_color'] ?? '#000000';

    if (empty($name) || empty($password)) {
        $error = "Имя и пароль обязательны!";
    } else {
        try {
            $stmt = $PDO->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$name]);
            if ($stmt->fetch()) {
                $error = "Пользователь с таким именем уже существует!";
            } else {
                $hash = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $PDO->prepare("INSERT INTO users(username, password, bg_color, text_color) VALUES (?, ?, ?, ?)");
                $stmt->execute([$name, $hash, $bg_color, $text_color]);
                $success = "Вы успешно зарегистрировались!";
            }
        } catch (Exception $e) {
            $error = "Ошибка при регистрации: " . $e->getMessage();
        }
    }
}
if (isset($_POST['EventofLogin'])) {
    $name = trim($_POST['loginName']);
    $password = $_POST['loginPassword'];

    if (empty($name) || empty($password)) {
        $loginError = "Имя и пароль обязательны!";
    } else {
        $stmt = $PDO->prepare("SELECT id, username, password, bg_color, text_color FROM users WHERE username = ?");
        $stmt->execute([$name]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];

            setcookie('bg_color', $user['bg_color'], time() + 30*24*3600, '/');
            setcookie('text_color', $user['text_color'], time() + 30*24*3600, '/');
            $bg = $user['bg_color'];
            $text = $user['text_color'];
        } else {
            $loginError = "Неверное имя или пароль!";
        }
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    setcookie('bg_color', '', time() - 3600, '/');
    setcookie('text_color', '', time() - 3600, '/');
    header('Location: index.php');
    exit;
}

if (isset($_SESSION['user_id'])) {
    $stmt = $PDO->prepare("SELECT bg_color, text_color FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $prefs = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($prefs) {
        $bg = $prefs['bg_color'];
        $text = $prefs['text_color'];
        setcookie('bg_color', $bg, time() + 30*24*3600, '/');
        setcookie('text_color', $text, time() + 30*24*3600, '/');
    }
}
$bg = $bg ?? (isset($_COOKIE['bg_color']) ? $_COOKIE['bg_color'] : '#ffffff');
$text = $text ?? (isset($_COOKIE['text_color']) ? $_COOKIE['text_color'] : '#000000');
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title><?php echo isset($_SESSION['user_id']) ? 'Личный кабинет' : 'Регистрация / Вход'; ?></title>
    <style>
        body {
            background-color: <?php echo htmlspecialchars($bg); ?>;
            color: <?php echo htmlspecialchars($text); ?>;
            font-family: Arial, sans-serif;
            padding: 20px;
        }
        .form-container {
            max-width: 500px;
            margin: 20px 0;
        }
        input[type="text"], input[type="password"], input[type="color"] {
            width: 100%;
            padding: 8px;
            margin: 5px 0 15px;
            box-sizing: border-box;
        }
        button, input[type="submit"] {
            padding: 10px 20px;
            background: #007bff;
            color: white;
            border: none;
            cursor: pointer;
        }
        button:hover { background: #0056b3; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>

<?php if (isset($_SESSION['user_id'])): ?>
    <h1>Добро пожаловать, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
    <p>Ваши настройки применены.</p>
    <a href="?logout">Выйти</a>
    <div class="form-container">
        <h2>Изменить настройки</h2>
        <form method="post" action="save_settings.php">
            <label>Фон: <input type="color" name="bg_color" value="<?php echo htmlspecialchars($bg); ?>"></label><br>
            <label>Текст: <input type="color" name="text_color" value="<?php echo htmlspecialchars($text); ?>"></label><br>
            <button type="submit">Сохранить</button>
        </form>
    </div>

<?php else: ?>
    <div class="form-container">
        <h2>Регистрация</h2>
        <?php if (!empty($error)) echo '<p class="error">' . htmlspecialchars($error) . '</p>'; ?>
        <?php if (!empty($success)) echo '<p class="success">' . htmlspecialchars($success) . '</p>'; ?>
        <form method="post">
            <p>Имя:</p>
            <input type="text" name="userName" placeholder="Введите ваше имя" required>
            <p>Пароль:</p>
            <input type="password" name="password" placeholder="Введите пароль" required>
            <p>Цвет фона:</p>
            <input type="color" name="bg_color" value="#ffffff">
            <p>Цвет текста:</p>
            <input type="color" name="text_color" value="#000000">
            <button type="submit" name="EventofRegistration">Зарегистрироваться</button>
        </form>
    </div>

    <div class="form-container">
        <h2>Вход</h2>
        <?php if (!empty($loginError)) echo '<p class="error">' . htmlspecialchars($loginError) . '</p>'; ?>
        <form method="post">
            <p>Имя:</p>
            <input type="text" name="loginName" placeholder="Ваше имя" required>
            <p>Пароль:</p>
            <input type="password" name="loginPassword" placeholder="Ваш пароль" required>
            <button type="submit" name="EventofLogin">Войти</button>
        </form>
    </div>
<?php endif; ?>

</body>
</html>