<?php
// Original author: takeshix@adversec.com
// Heavily modified by skinner927@gmail.com

define('WINNINGFLAG', 'A ROLLING PROGRAM SMASHED THE GENIUS');
define('BOTCOOKIE', 'mag1c_c00k1e007');
define('COMMENTDIR', './comments/'); // must have trailing slash

// Constants so we can't screw up as easy
define('NAME', 'name');
define('BOTID', 'botid');
define('COMMENT', 'comment');
define('USERNAME', 'username');

// Let's enable XSS on this website
header('X-XSS-Protection: 0');
header('Access-Control-Allow-Origin: *');

function sanitizeAlphaNum($session)
{
  return preg_replace('/[^A-Za-z0-9]/', '', $session);
}

// Bot passes us what user we want to look at
$session = NULL;
if ($_COOKIE[BOTID] === BOTCOOKIE) {
  $session = sanitizeAlphaNum($_COOKIE[NAME]);
} else if (isset($_REQUEST[NAME]) && !empty($_REQUEST[NAME])) {
  // This is a regular user, extract the name param
  $session = sanitizeAlphaNum($_REQUEST[NAME]);
}

// Redirect if no named session
if ($session === NULL) {
  // Generate a new session for this fool
  header('Location: ' . $_SERVER['REQUEST_URI'] . '?' . NAME . '=' . md5(uniqid(rand(), true)));
  die('redirect new name');
}

// prefix for all file names from this session (so we only see this session's filenames)
$filePrefix = $session . '-';

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST[COMMENT])
    && !empty($_POST[COMMENT]) && isset($_POST[USERNAME]) && !empty($_POST[USERNAME])
) {
  $file_name = $filePrefix . time() . '-' . substr(md5(uniqid(rand(), true)), 0, 4);
  $fh = fopen(COMMENTDIR . $file_name, 'w+');
  fwrite($fh, trim($_POST[USERNAME]) . "\n" . $_POST[COMMENT]);
  fclose($fh);
  header('HTTP/1.1 303 See Other');
  header('Location: ' . $_SERVER['REQUEST_URI']);
  die('redirecting');
}
?>
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>Picture of the week</title>
  <script src="/node_modules/jquery/dist/jquery.min.js"></script>
  <script>$.support.cors = true;</script>
</head>
<body>
<?php
if ($_COOKIE["PHPSESSID"] === BOTCOOKIE) {
  echo '<span id="flag">the flag is: ' . WINNINGFLAG . '</span>';
}
?>
<form method="post">
  <table style="width: 1000px;table-layout: fixed">
    <tr style="vertical-align: top">
      <th rowspan="100" width="600px">
        <h3>Picture of the week:</h3>
        <img src="/image.jpg" />
      </th>
    </tr>
    <tr width="400">
      <td colspan="2">
        <h3>Post a comment:</h3>
        <div id="name">Hello <?= $session ?></div>
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <label for="<?= USERNAME ?>">Username:</label>
        <input type="text" name="<?= USERNAME ?>" style="width: 100%"/>
      </td>
    </tr>
    <tr>
      <td colspan="2">
        <label for="<?= COMMENT ?>">Comment:</label>
        <textarea name="<?= COMMENT ?>" style="width: 100%"></textarea>
      </td>
    </tr>
    <tr>
      <td colspan="2" style="text-align: center">
        <input type="submit" value="Post it!"/>
      </td>
    </tr>
    <tr>
      <td colspan="2"><h3>Comments:</h3></td>
    </tr>
    <?php
    $dh = opendir(COMMENTDIR);
    $files = [];
    while ($file = readdir($dh)) {
      if (strpos($file, '.') !== 0 && strpos($file, $filePrefix) === 0) {
        $files[] = $file;
      }
    }
    sort($files);
    foreach($files as $file){
      $content = file(COMMENTDIR . $file);
      $body = implode(array_slice($content, 1));
      echo "<tr style='border: 1px dotted black'>\n";
      echo "\t<td colspan='2' style='word-wrap: break-word;padding: 5px;'>Submitted by: <b>$content[0]</b></td>\n";
      echo "<tr style='border: 1px dotted black'>\n";
      echo "</tr>\n";
      echo "\t<td colspan='2' style='border: 1px dotted black;word-wrap: break-word;padding: 5px; white-space: pre-wrap'>$body</td>\n";
      echo "</tr>\n";
    }
    ?>
  </table>
</form>
</body>
</html>
