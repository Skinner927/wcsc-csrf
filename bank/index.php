<?php

// Sets session cookies to set for 3 days, secure = false, httponly = false
session_set_cookie_params(60*60*24*3, false, false);

header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Origin: http://board.wcsc');
header('Access-Control-Allow-Headers: Content-Type, *');
header('X-XSS-Protection: 0');

// Load jQuery to be nice.
echo '<script src="/node_modules/jquery/dist/jquery.min.js"></script>';
// This is a hack for jquery ajax to work on zombie.js
echo '<script>$.support.cors = true;</script>';

/**
 * This script has been modified to use flat user files instead of a sqlite db.
 *
 *
 * Class OneFileLoginApplication
 *
 * An entire php application with user registration, login and logout in one file.
 * Uses very modern password hashing via the PHP 5.5 password hashing functions.
 * This project includes a compatibility file to make these functions available in PHP 5.3.7+ and PHP 5.4+.
 *
 * @author Panique
 * @link https://github.com/panique/php-login-one-file/
 * @license http://opensource.org/licenses/MIT MIT License
 */
class OneFileLoginApplication
{

  /**
   * @var string Path to store users in (create this with _install.php)
   */
  private $user_dir = "./users";

  /**
   * @var object FlatUserMgmt
   */
  private $user_mgmt = null;

  /**
   * @var bool Login status of user
   */
  private $user_is_logged_in = false;

  /**
   * @var string System messages, likes errors, notices, etc.
   */
  public $feedback = "";


  /**
   * Does necessary checks for PHP version and PHP password compatibility library and runs the application
   */
  public function __construct()
  {
    if ($this->performMinimumRequirementsCheck()) {
      $this->createDatabaseConnection();

      $this->runApplication();
    }
  }

  /**
   * Performs a check for minimum requirements to run this application.
   * Does not run the further application when PHP version is lower than 5.3.7
   * Does include the PHP password compatibility library when PHP version lower than 5.5.0
   * (this library adds the PHP 5.5 password hashing functions to older versions of PHP)
   * @return bool Success status of minimum requirements check, default is false
   */
  private function performMinimumRequirementsCheck()
  {
    if (version_compare(PHP_VERSION, '5.3.7', '<')) {
      echo "Sorry, Simple PHP Login does not run on a PHP version older than 5.3.7 !";
    } elseif (version_compare(PHP_VERSION, '5.5.0', '<')) {
      require_once("libraries/password_compatibility_library.php");
      return true;
    } elseif (version_compare(PHP_VERSION, '5.5.0', '>=')) {
      return true;
    }
    // default return
    return false;
  }

  /**
   * This is basically the controller that handles the entire flow of the application.
   */
  public function runApplication()
  {
    // DEBUG
    if($_REQUEST['action'] === 'barf'){
      $this->showPageBarf();
      return;
    }

    // check is user wants to see register page (etc.)
    if (isset($_GET["action"]) && $_GET["action"] == "register") {
      $this->doRegistration();
      $this->showPageRegistration();
    } else {
      // start the session, always needed!
      $this->doStartSession();
      // check for possible user interactions (login with session/post data or logout)
      $this->performUserLoginAction();
      // show "page", according to user's login status
      if ($this->getUserLoginStatus()) {
        $this->showPageLoggedIn();
      } else {
        $this->showPageLoginForm();
      }
    }
  }

  /**
   * Creates a PDO database connection (in this case to a SQLite flat-file database)
   * @return bool Database creation success status, false by default
   */
  private function createDatabaseConnection()
  {
    if(!is_null($this->user_mgmt)){
      return true;
    }
    $this->user_mgmt = new FlatUserMgmt($this->user_dir);
    return !is_null($this->user_mgmt);
  }

  /**
   * Handles the flow of the login/logout process. According to the circumstances, a logout, a login with session
   * data or a login with post data will be performed
   */
  private function performUserLoginAction()
  {
    if (isset($_GET["action"]) && $_GET["action"] == "logout") {
      $this->doLogout();
    } elseif (!empty($_SESSION['user_name']) && ($_SESSION['user_is_logged_in'])) {
      $this->doLoginWithSessionData();
    } elseif (isset($_POST["login"])) {
      $this->doLoginWithPostData();
    }
  }

  /**
   * Simply starts the session.
   * It's cleaner to put this into a method than writing it directly into runApplication()
   */
  private function doStartSession()
  {
    if(session_status() == PHP_SESSION_NONE) session_start();
  }

  /**
   * Set a marker (NOTE: is this method necessary ?)
   */
  private function doLoginWithSessionData()
  {
    $this->user_is_logged_in = true; // ?
  }

  /**
   * Process flow of login with POST data
   */
  private function doLoginWithPostData()
  {
    if ($this->checkLoginFormDataNotEmpty()) {
      if ($this->createDatabaseConnection()) {
        $this->checkPasswordCorrectnessAndLogin();
      }
    }
  }

  /**
   * Logs the user out
   */
  private function doLogout()
  {
    $_SESSION = array();
    session_destroy();
    $this->user_is_logged_in = false;
    $this->feedback = "You were just logged out.";
  }

  /**
   * The registration flow
   * @return bool
   */
  private function doRegistration()
  {
    if ($this->checkRegistrationData()) {
      if ($this->createDatabaseConnection()) {
        $this->createNewUser();
      }
    }
    // default return
    return false;
  }

  /**
   * Validates the login form data, checks if username and password are provided
   * @return bool Login form data check success state
   */
  private function checkLoginFormDataNotEmpty()
  {
    if (!empty($_POST['user_name']) && !empty($_POST['user_password'])) {
      return true;
    } elseif (empty($_POST['user_name'])) {
      $this->feedback = "Username field was empty.";
    } elseif (empty($_POST['user_password'])) {
      $this->feedback = "Password field was empty.";
    }
    // default return
    return false;
  }

  /**
   * Checks if user exits, if so: check if provided password matches the one in the database
   * @return bool User login success status
   */
  private function checkPasswordCorrectnessAndLogin()
  {
    $user = $this->user_mgmt->getUser($_POST['user_name']);
    if($user) {
      if($this->user_mgmt->validateUserPass($_POST['user_name'], $_POST['user_password'])){
        // write user data into PHP SESSION [a file on your server]
        $_SESSION['user_name'] = $user->username;
        $_SESSION['user_is_logged_in'] = true;
        $this->user_is_logged_in = true;
        return true;
      } else {
        $this->feedback = "Wrong password.";
      }
    } else {
      $this->feedback = 'This user does not exist.';
    }
    // default return
    return false;
  }

  /**
   * Validates the user's registration input
   * @return bool Success status of user's registration data validation
   */
  private function checkRegistrationData()
  {
    // if no registration form submitted: exit the method
    if (!isset($_POST["register"])) {
      return false;
    }

    // validating the input
    if (!empty($_POST['user_name'])
        && strlen($_POST['user_name']) <= 64
        && strlen($_POST['user_name']) >= 2
        && preg_match('/^[a-z\d]{2,64}$/i', $_POST['user_name'])
        && !empty($_POST['user_password_new'])
        && !empty($_POST['user_password_repeat'])
        && ($_POST['user_password_new'] === $_POST['user_password_repeat'])
    ) {
      // only this case return true, only this case is valid
      return true;
    } elseif (empty($_POST['user_name'])) {
      $this->feedback = "Empty Username";
    } elseif (empty($_POST['user_password_new']) || empty($_POST['user_password_repeat'])) {
      $this->feedback = "Empty Password";
    } elseif ($_POST['user_password_new'] !== $_POST['user_password_repeat']) {
      $this->feedback = "Password and password repeat are not the same";
    } elseif (strlen($_POST['user_name']) > 64 || strlen($_POST['user_name']) < 2) {
      $this->feedback = "Username cannot be shorter than 2 or longer than 64 characters";
    } elseif (!preg_match('/^[a-z\d]{2,64}$/i', $_POST['user_name'])) {
      $this->feedback = "Username does not fit the name scheme: only a-Z and numbers are allowed, 2 to 64 characters";
    } else {
      $this->feedback = "An unknown error occurred.";
    }

    // default return
    return false;
  }

  /**
   * Creates a new user.
   * @return bool Success status of user registration
   */
  private function createNewUser()
  {
    // remove html code etc. from username
    $username = $_POST['user_name'];
    $password = $_POST['user_password_new'];

    $user = $this->user_mgmt->getUser($username);
    if($user !== false){
      $this->feedback = "Sorry, that username is already taken. Please choose another one.";
      return false;
    }

    $user = $this->user_mgmt->createUser($username, $password);
    if ($user !== false) {
      $this->feedback = "Your account has been created successfully. You can now log in.";
      return true;
    } else {
      $this->feedback = "Sorry, your registration failed. Please go back and try again.";
    }
    return false;
  }

  /**
   * Simply returns the current status of the user's login
   * @return bool User's login status
   */
  public function getUserLoginStatus()
  {
    return $this->user_is_logged_in;
  }

  /**
   * Simple demo-"page" that will be shown when the user is logged in.
   * In a real application you would probably include an html-template here, but for this extremely simple
   * demo the "echo" statements are totally okay.
   */
  private function showPageLoggedIn()
  {
    if ($this->feedback) {
      echo $this->feedback . "<br/><br/>";
    }

    $user = $this->user_mgmt->getUser($_SESSION['user_name']);

    echo '<div>Hello <span id="username">' . $_SESSION['user_name'] . '</span>, you are logged in.</div><br/><br/>';
    echo '<a href="' . $_SERVER['SCRIPT_NAME'] . '?action=logout">Log out</a>';

    echo '<br><br>';

    echo '<div id="secret-msg">Super Secret: <span id="secret">'.$user->secret.'</span></div>';

    echo '<br><div><img src="/bank.jpg" /></div>';
  }

  /**
   * Simple demo-"page" with the login form.
   * In a real application you would probably include an html-template here, but for this extremely simple
   * demo the "echo" statements are totally okay.
   */
  private function showPageLoginForm()
  {
    if ($this->feedback) {
      echo $this->feedback . "<br/><br/>";
    }

    echo '<h2>Bank Login</h2>';

    echo '<form method="post" action="' . $_SERVER['SCRIPT_NAME'] . '" name="loginform">';
    echo '<label for="login_input_username">Username</label> ';
    echo '<input id="login_input_username" type="text" name="user_name" required /> ';
    echo '<label for="login_input_password">Password</label> ';
    echo '<input id="login_input_password" type="password" name="user_password" required /> ';
    echo '<input type="submit"  name="login" value="Log in" />';
    echo '</form>';

    echo '<a href="' . $_SERVER['SCRIPT_NAME'] . '?action=register">Register new account</a>';
    echo '<br><div><img src="/bank.jpg" /></div>';
  }

  /**
   * Simple demo-"page" with the registration form.
   * In a real application you would probably include an html-template here, but for this extremely simple
   * demo the "echo" statements are totally okay.
   */
  private function showPageRegistration()
  {
    if ($this->feedback) {
      echo $this->feedback . "<br/><br/>";
    }

    echo '<h2>Registration</h2>';

    echo '<form method="post" action="' . $_SERVER['SCRIPT_NAME'] . '?action=register" name="registerform">';
    echo '<label for="login_input_username">Username (only letters and numbers, 2 to 64 characters)</label>';
    echo '<input id="login_input_username" type="text" pattern="[a-zA-Z0-9]{2,64}" name="user_name" required />';
    echo '<label for="login_input_password_new">Password (min. 6 characters)</label>';
    echo '<input id="login_input_password_new" class="login_input" type="password" name="user_password_new" required autocomplete="off" />';
    echo '<label for="login_input_password_repeat">Repeat password</label>';
    echo '<input id="login_input_password_repeat" class="login_input" type="password" name="user_password_repeat" required autocomplete="off" />';
    echo '<input type="submit" name="register" value="Register" />';
    echo '</form>';

    echo '<a href="' . $_SERVER['SCRIPT_NAME'] . '">Homepage</a>';
  }

  private function showPageBarf(){
    echo 'POST:<br><pre>'.print_r($_POST, true).'</pre><br><br><br>';
    echo 'GET:<br><pre>'.print_r($_GET, true).'</pre><br><br><br>';
    echo 'COOKIES:<br><pre>'.print_r($_COOKIE, true).'</pre><br><br><br>';
    echo 'SESSION:<br><pre>'.print_r($_SESSION, true).'</pre><br><br><br>';
  }
}

class FlatUserMgmt
{
  private $dir = './users';
  private $files = [];

  public function __construct($dir=null)
  {
    if(!is_null($dir)){
      $this->dir = $dir;
    }

    // Ensure no trailing slash
    // this will turn '/' into '' which is ok
    // and './' to '.' which is ok too
    // because when we use dir we'll always + '/' to it.
    while(substr($this->dir, -1) === '/'){
      $this->dir = substr($this->dir, 0, -1);
    }

    $this->fillFilesArray();
  }

  public function getUser($username){
    if(!in_array($username, $this->files)){
      return false;
    }

    $fp = $this->getUserFilePath($username);
    if($fp === false){
      return false;
    }

    return json_decode(file_get_contents($fp));
  }

  public function validateUserPass($username, $pass)
  {
    $user = $this->getUser($username);
    if(!$user){
      return false;
    }

    return password_verify($pass, $user->pass_hash);
  }

  public function createUser($username, $password){
    $username = $this->sanitizeAlphaNum($username);
    // crypt the user's password with the PHP 5.5's password_hash() function, results in a 60 char hash string.
    // the constant PASSWORD_DEFAULT comes from PHP 5.5 or the password_compatibility_library
    $password = password_hash($password, PASSWORD_DEFAULT);
    $secret = md5(time() . $username);

    $fp = $this->craftUserFilePath($username);

    if(file_exists($fp)){
      return false;
    }

    umask(0774);
    $result = file_put_contents($fp, json_encode(array(
      'username' => $username,
      'pass_hash' => $password,
      'secret' => $secret
    )));

    if($result !== false){
      $this->fillFilesArray();
      return true;
    }
    return false;
  }

  private function getUserFilePath($username){
    $username = $this->sanitizeAlphaNum($username);

    if(!in_array($username, $this->files)){
      return false;
    }

    return $this->craftUserFilePath($username);
  }

  private function craftUserFilePath($username){
    $username = $this->sanitizeAlphaNum($username);
    return $this->dir . '/' . $username;
  }

  private function sanitizeAlphaNum($str)
  {
    return preg_replace('/[^A-Za-z0-9]/', '', $str);
  }

  private function fillFilesArray(){
    // Find all the user files
    $dh = opendir($this->dir);
    $files = [];
    while($file = readdir($dh))
    {
      if(strpos($file, '.') !== 0)
      {
        $files[] = $file;
      }
    }
    $this->files = $files;
  }
}

// run the application
$application = new OneFileLoginApplication();
