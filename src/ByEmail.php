<?php
namespace IO\OTP;
use TymFrontiers\Data,
    TymFrontiers\BetaTym,
    TymFrontiers\Generic,
    TymFrontiers\InstanceError,
    TymFrontiers\MySQLDatabase,
    TymFrontiers\MultiForm,
    TymFrontiers\Validator,
    IO\Email,
    IO\Mailer,
    IO\Email\Recipient;

use function IO\code_split,
             IO\generate_code,
             IO\get_constant,
             \get_database,
             \get_dbserver,
             \get_dbuser,
             \db_cred,
             IO\setting_set_value;

class ByEmail {
    use \TymFrontiers\Helper\MySQLDatabaseObject,
      \TymFrontiers\Helper\Pagination;

  protected static $_primary_key='code';
  protected static $_db_name;
  protected static $_table_name = "otp";
  protected static $_db_fields = ["code", "token", "reference", "user", "sender", "receiver", "message", "expiry", "_created"];

  const PREFIX = "OTP";
  const PREFIX_CODE = "495";

  private $code;
  public $token;
  protected $reference = NULL;
  protected $user;
  public $sender;
  public $receiver;
  public $message;
  public $expiry;
  protected $_created;
  
  private static $data_obj;
  public $errors = [];
  
  function __construct (mixed $code = "", $conn = false) {
    // server name
    if (!$srv = get_constant("PRJ_EMAIL_SERVER")) {
      throw new \Exception("Email server not defined", 1);
    }
    // database name
    if (!$db_name = get_database("email", $srv)) {
      throw new \Exception("Email database name not set", 1);
    } 
    self::$_db_name = $db_name;
    // database server
    if (!$db_server = get_dbserver($srv)) {
      throw new \Exception("Email database-server not set", 1);
    } 
    // Check @var $conn
    if ($conn && $conn instanceof MySQLDatabase && $conn->getServer() == $db_server ) {
      self::_setConn($conn);
    } else {
      global $session;
      // database user
      if (!$db_user = get_dbuser($srv, $session->access_group())) {
        throw new \Exception("Email database-user not set for [{$session->access_group()}]", 1);
      }
      // set database connection
      $conn = new MySQLDatabase($db_server, $db_user[0], $db_user[1], $db_name);
      self::_setConn($conn);
    }

    if ($code && $code = (new Validator)->pattern($code, ["code","pattern", "/^495([\d]{4,4})([\d]{4,4})$/"])) {
      if ($found = self::findById($code)) {
        foreach ($found as $prop=>$value) {
          $this->$prop = $value;
        }
      }
    }
    self::$data_obj = new Data;
  }
  public function setMessage (string $message):bool {
    if ($message = (new Validator)->script($message, ["message", "script", 15, 1024])) {
      if (!\str_contains($message, "%{token}")) {
        throw new \Exception("Message must contain [token] or replace-pattern %{token}.", 1);
      } else {
        $this->message = $message;
        return true;
      }
    }
    return false;
  }

  public function setReceiver (mixed $receiver):bool {
    $valid = new Validator;
    if (\is_array($receiver)) {
      if (!empty ($receiver["email"]) && $email = $valid->email($receiver["email"], ["receiver", "email"])) {
        $this->user = $email;
        $this->receiver = empty($receiver["name"]) ? $email : "{$receiver['name']} {$receiver['surname']} <{$email}>";
        return true;
      }
    } else {
      if ($email = $valid->email($receiver, ["receiver", "email"])) {
        $this->user = $this->receiver = $email;
        return true;
      }
    }
    return false;
  }
  public function setSender (mixed $sender):bool {
    $valid = new Validator;
    if (\is_array($sender)) {
      if (!empty ($sender["email"]) && $email = $valid->email($sender["email"], ["sender", "email"])) {
        $this->sender = empty($sender["name"]) ? $email : "{$sender['name']} {$sender['surname']} <{$email}>";
        return true;
      }
    } else {
      if ($email = $valid->email($sender, ["sender", "email"])) {
        $this->sender = $email;
        return true;
      }
    }
    return false;
  }
  public function setToken (string $token):bool {
    $valid = new Validator;
    if ($token = $valid->username($token, ["token", "username", 6, 21, [], "MIXED"])) {
      $this->token = $token;
      return true;
    }
    return false;
  }
  public function send (string $token_type = "", int $expiry = 0) {
    global $code_prefix;
    $token_types = [
      Data::RAND_LOWERCASE,
      Data::RAND_MIXED,
      Data::RAND_MIXED_LOWER,
      Data::RAND_MIXED_UPPER,
      Data::RAND_NUMBERS,
      Data::RAND_UPPERCASE
    ];
    $token_type = \in_array($token_type, $token_types) ? $token_type : Data::RAND_MIXED_UPPER;
    $this->expiry = $expiry < 1 ? \date(BetaTym::MYSQL_DATETIME_STRING, \strtotime("+1 Day")) : \date(BetaTym::MYSQL_DATETIME_STRING, $expiry);
    $this->code = generate_code(self::PREFIX_CODE, Data::RAND_NUMBERS, 11, $this, "code", true);
    $token = empty($this->token) ? Data::uniqueRand('', 7, $token_type, false) : $this->token;
    $this->token = self::$data_obj->encodeEncrypt($token);
    $token = code_split($token, " ");
    if (empty($this->message)) {
      $msg = "**%{token}** is your One Time Passcode ".PHP_EOL.PHP_EOL;
      $msg .= " Kindly keep this message safe and do not share with anyone. If you did not initiate any request warranting OTP, please ignore this message.";
      $this->message = $msg;
    }
    $message = \str_replace("%{token}", $token, $this->message);

    // try to send message before saving record
    $sender = new Mailer\Profile(Generic::splitEmailName($this->sender), "", "", self::$_conn);
    $eml = new Email("","", self::$_conn);
    $receiver = new Recipient($eml->code(), Generic::splitEmailName($this->receiver), "to", "", self::$_conn);
    $eml->prep("35284847827", "OTP from ". get_constant("PRJ_TITLE"), $message);
    if ($eml->send($sender, $receiver, false)) {
      $this->reference = $eml->thread();
      if (!$this->_create()) {
        $errs = (new InstanceError(self::$_conn, true))->get("query", true);
        foreach ($errs as $er) {
          $this->errors["send"][] = [1, 256, $er, __FILE__, __DIR__];
        }
        return false;
      }
      return $this->code;
    }
    return false;
  }
  public function resend () {
    if (\str_contains(self::$_conn->getUser(), "GUEST")) {
      // create elevated connection
      $eml_server = get_constant("PRJ_EMAIL_SERVER");
      $dev_usr = db_cred($eml_server, "DEVELOPER");
      $conn = new MySQLDatabase(get_dbserver($eml_server), $dev_usr[0], $dev_usr[1]);
      self::_setConn($conn);
    }
    if ((!empty($this->message) && !empty($this->sender) && !empty($this->receiver) && !empty($this->token)) && $token = self::$data_obj->decodeDecrypt($this->token) ) {
      $message = \str_replace("%{token}", code_split($token, " "), $this->message);
      // try to send message before saving record
      $sender = new Mailer\Profile(Generic::splitEmailName($this->sender), "", "", self::$_conn);
      $eml = new Email("", "", self::$_conn);
      $receiver = new Recipient($eml->code(), Generic::splitEmailName($this->receiver), "to", "", self::$_conn);
      $eml->prep("35284847827", "OTP from ". get_constant("PRJ_TITLE"), $message, $this->reference);
      return $eml->send($sender, $receiver, false) ? $this->code : false;
    }
    return false;
  }
  public function verify (string $user, string $token):bool {
    $user = self::$_conn->escapeValue($user);
    $return = false;
    $query = "SELECT `token` 
              FROM :db:.:tbl: 
              WHERE `user` = '{$user}'
              AND _created > DATE_SUB(NOW(), INTERVAL 24 HOUR)
              AND (
                expiry IS NULL
                OR expiry = ''
                OR expiry > NOW()
              )
              ORDER BY _created DESC 
              LIMIT 1";
    if (!empty($token) && $found = self::findBySql($query)) {
      foreach ($found as $otp) {
        $otp_token = self::$data_obj->decodeDecrypt($otp->token);
        if ($otp_token && $otp_token == $token) {
          $return = true;
          break;
        }
      }
    }
    return $return;
  }

}
