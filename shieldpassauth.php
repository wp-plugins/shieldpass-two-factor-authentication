<?php
/* Script handling the actual Shieldpass authentication
 */

error_reporting(0);

require_once('../../../wp-config.php');
require_once('shieldpasslib.php');

if ( isset($_POST['shieldpass_card_id']) && isset($_POST['shieldpass_user_response']) ) {

	$shieldpass_card_id = htmlentities($_POST["shieldpass_card_id"], ENT_QUOTES, 'UTF-8');
	$shieldpass_user_response = htmlentities($_POST['shieldpass_user_response'], ENT_QUOTES, 'UTF-8');
	
	if ( ($_POST['wpuser'] == "") || ($_POST['wppw'] == "") ) { // direct authentication from shieldpass.com
		?><html>
		<head>
		</head>
		<body>
		<form action="" method="post" name="form">
		<input type="hidden" name="shieldpass_card_id" value="<?php echo $shieldpass_card_id;?>" />
		<input type="hidden" name="shieldpass_user_response" value="<?php echo $shieldpass_user_response;?>" />
		<input type="hidden" name="direct_authentication" value="yes" />
		<div align="center" style="font-family:Arial">
		<nobr>WordPress Username:<input type="text" name="wpuser" value="" /></nobr><br>
		<nobr>WordPress Password:<input type="password" name="wppw" value="" /></nobr><br>
		<input type="submit" value="Click here to submit your WordPress username and password." />
		</div>
		</form>
		</body></html><?php
		exit();
	} else { // all values are present
	
	$wpuser = htmlentities($_POST["wpuser"], ENT_QUOTES, 'UTF-8');
	$wppw = htmlentities($_POST["wppw"], ENT_QUOTES, 'UTF-8');
	
	if ( $_POST['direct_authentication'] == "yes" ) {
		$password = shieldpass_encrypt(get_spsecretkey(), $wppw);
	} else {
		$password = $wppw;
	}
    ?><html>
    <head>
    </head>
    <body>
    <form action="../../../wp-login.php" method="post" name="form">
    <input type="hidden" name="shieldpass_card_id" value="<?php echo $shieldpass_card_id;?>" />
    <input type="hidden" name="shieldpass_user_response" value="<?php echo $shieldpass_user_response;?>" />
    <input type="hidden" name="wpuser" value="<?php echo $wpuser;?>" />
    <input type="hidden" name="wppw" value="<?php echo $password; ?>" />
    <input type="submit" value="You will be redirected in a few seconds. If this doesn't work click here." />
    </form>
	<script type='text/javascript'>document.form.submit();</script>
    </body></html><?php
	exit();
	}
	
} elseif ( isset($_GET['user']) && isset($_GET['password']) ) {
	check_admin_referer('shieldpass-plugin-authenticate_wordpress'); // check nonce
    $wpdb = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);

    if (mysqli_connect_errno()) {
        printf("Connection failed: %s\n", mysqli_connect_error());
        exit();
    }

    //fetching wordpress userid
    $result=$wpdb->prepare("SELECT ID FROM ".$table_prefix."users WHERE user_login=?");
    $result->bind_param('s',$_GET['user']);
    $result->execute();
    $result->bind_result($wpuid);
    $result->fetch();
    $result->free_result();
    //fetching shieldpass userid
    $result=$wpdb->prepare("SELECT spuid FROM ".$table_prefix."shieldpass WHERE wpuid=?");
    $result->bind_param('i', $wpuid);
    $result->execute();
    $result->bind_result($spuid);
    $result->fetch();
    $result->free_result();

    //fetching secret and public key
    $spsecretkeyopt='shieldpass_secretkey';
    $sppublickeyopt='shieldpass_publickey';
	$transid = "";

    $result=$wpdb->prepare("SELECT option_value FROM ".$table_prefix."options WHERE option_name=?");
    $result->bind_param('s', $spsecretkeyopt);
    $result->execute();
    $result->store_result();
    $result->bind_result($spsecretkey);
    $result->fetch();
    $result->reset();

    $result->bind_param('s', $sppublickeyopt);
    $result->execute();
    $result->bind_result($sppublickey);
    $result->fetch();
    
    $result->free_result();
    $wpdb->close();

	$user = htmlentities($_GET["user"], ENT_QUOTES, 'UTF-8');
	$password = htmlentities($_GET["password"], ENT_QUOTES, 'UTF-8');
    ?><form id="shieldpass_form" method="post">
    <input type="hidden" name="wpuser" value="<?php echo $user;?>" />
    <input type="hidden" name="wppw" value="<?php echo $password;?>" />
    <?php 
	$lockedout = "<br><br>If you now find yourself locked out of WordPress we suggest you login with FTP and rename the */wp-content/plugins/shieldpass-two-factor-authentication/ folder to something else which will disable the shieldpass authentication so you can login normally";
	if ( $sppublickey == "" ) die("you must set the public key in WordPress ShieldPass configuration $lockedout");
	if ( $spsecretkey == "" ) die("you must set the secret key in WordPress ShieldPass configuration $lockedout");
	if ( $spuid == "" ) die("you must set the card id in WordPress ShieldPass configuration $lockedout");
	echo shieldpass_get_html($sppublickey, $spsecretkey, $spuid, $transid);?>
    </form><?php
}

?>