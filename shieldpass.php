<?php
/*
Plugin Name: Shieldpass two-factor authentication
Plugin URI: https://www.shieldpass.com/wordpress.html
Description: This plugin adds shieldpass two-factor authentication to the Wordpress login page. Once activated you must go to Users > Shieldpass Configuration and configure a wordpress username to a shieldpass card ID from your https://www.shieldpass.com account. You will also need to enter your public and secret key which can also be found in your shieldpass.com account page.
Version: 2.2
Author: Matthias Kebeck
Author URI: https://www.shieldpass.com/about.html
License: GPL2
*/

/*
Copyright 2011 ShieldPass <admin@shieldpass.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2, as 
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
http://www.gnu.org/licenses/gpl.html

Plugin Installation Instructions:
1. Create an account at https://www.shieldpass.com and buy your ShieldPass access cards.
2. After signing up and activating your account, download the ShieldPass WordPress plugin zip file.
3. Install and activate the ShieldPass WordPress plugin.
4. In the users setting, select ShieldPass Configuration and fill in the "Public Key" and "Secret Key" generated in your ShieldPass administrative panel. Also, enter the WordPress user and corresponding ShieldPass card ID value that you'd like to require ShieldPass login.
5. Log out of your WordPress. Upon logging back in, you'll be prompted to superimpose your access card using ShieldPass's two-factor authentication service.
*/

require_once("shieldpasslib.php");

function get_sppublickey(){
    return get_option('shieldpass_publickey', 'No public key set!');
}

function get_spsecretkey(){
    return get_option('shieldpass_secretkey', 'No secret key set!');
}

function set_sppublickey($publickey){
    return update_option('shieldpass_publickey', $publickey);
}

function set_spsecretkey($secretkey){
    return update_option('shieldpass_secretkey', $secretkey);
}

function shieldpass_install(){
    global $wpdb;
    $sp_tablename=$wpdb->prefix."shieldpass";

    $sql="CREATE TABLE ".$sp_tablename." (
            id INT(9) NOT NULL AUTO_INCREMENT,
            spuid VARCHAR(255) DEFAULT '' NOT NULL,
            wpuid INT(9) NOT NULL,
            UNIQUE KEY id (id)
            );";

    require_once(ABSPATH.'wp-admin/includes/upgrade.php');
    dbDelta($sql);

    update_option('shieldpass_publickey', 'No public key set!');
    update_option('shieldpass_secretkey', 'No secret key set!');
    update_option('shieldpass_allownocardusers', 'true');

}
register_activation_hook(__FILE__, 'shieldpass_install');

function shieldpass_uninstall(){
    global $wpdb;
    $sp_tablename=$wpdb->prefix."shieldpass";

    $wpdb->query("DROP TABLE $sp_tablename;");
    
    delete_option('shieldpass_secretkey');
    delete_option('shieldpass_publickey');
    delete_option('shieldpass_allownocardusers');
}
register_deactivation_hook(__FILE__, 'shieldpass_uninstall');

function shieldpass_login_authenticate($user, $username, $password){
    global $wpdb;
    if ( isset($_POST["shieldpass_card_id"]) ){
		$shieldpass_card_id = htmlentities($_POST["shieldpass_card_id"], ENT_QUOTES, 'UTF-8');
		$shieldpass_user_response = htmlentities($_POST['shieldpass_user_response'], ENT_QUOTES, 'UTF-8');
		$wppw = htmlentities($_POST['wppw'], ENT_QUOTES, 'UTF-8');
		$wpuser = htmlentities($_POST['wpuser'], ENT_QUOTES, 'UTF-8');
	
        $spresp=shieldpass_check_answer(get_sppublickey(), get_spsecretkey(), $shieldpass_card_id, $shieldpass_user_response);
        
        if ( !$spresp->is_valid ) {
            return new WP_Error('sp_denied', __("<strong>ERROR:</strong> Authentication via Shieldpass failed."));
        } else {
            $password = shieldpass_decrypt(get_spsecretkey(), $wppw);
            return wp_authenticate_username_password($user, $wpuser, $password); 
        }
    } elseif ( !isset($_POST['log']) ) {//to prevent some weird bug showing up on the initial load of wp-login.php
        return wp_authenticate_username_password($user,$username,$password);
    } elseif ( isset($_POST['log']) ) {
        // log in users not associated with shieldpass card, if allowed to do so
		$log = mysql_real_escape_string($_POST['log']);
        $wpuser = get_userdatabylogin($log);
        $result = $wpdb->get_results("SELECT COUNT(*) FROM ".$wpdb->prefix."shieldpass WHERE wpuid='".$wpuser->ID."'", ARRAY_A);
        if ( ($result[0]['COUNT(*)'] == 0) && (get_option('shieldpass_allownocardusers', 'true') == 'true') ) {
            return wp_authenticate_username_password($user, $username, $password);
        } elseif ( ($result[0]['COUNT(*)'] == 0) && (get_option('shieldpass_allownocardusers', 'true') == 'false') ) {
            return false;
        }

        $lockedout = "<br><br>If you now find yourself locked out of WordPress we suggest you login with FTP and rename the */wp-content/plugins/shieldpass-two-factor-authentication/ folder to something else which will disable the shieldpass authentication so you can login normally";
		if ( (get_spsecretkey() == "") || (get_spsecretkey() == "No secret key set!") ) die("<br><b>Warning:</b>You must set the secret key in WordPress ShieldPass configuration $lockedout");
		$password = shieldpass_encrypt(get_spsecretkey(), $_POST['pwd']);
        $shieldpassauthpath = preg_replace("/wp-login\.php/", "wp-content/plugins/shieldpass-two-factor-authentication/shieldpassauth.php", $_SERVER['SCRIPT_NAME']);
        if ( $_SERVER['HTTPS'] == 'on' ) {
			$link = 'https://'.$_SERVER['SERVER_NAME'].$shieldpassauthpath.'?user='.$log.'&password='.$password;
		} else {
			$link = 'http://'.$_SERVER['SERVER_NAME'].$shieldpassauthpath.'?user='.$log.'&password='.$password;
		}
		$link = ( function_exists('wp_nonce_url') ) ? wp_nonce_url($link, 'shieldpass-plugin-authenticate_wordpress') : $link;
		$link = str_replace( '&amp;', '&', $link );
		header("Location: $link");
		exit();
    }

    return false;
}
remove_action('authenticate', 'wp_authenticate_username_password', 20, 3);
add_action('authenticate', 'shieldpass_login_authenticate', 20, 3);

function shieldpass_adminpanel(){
    global $wpdb;

	if ( isset($_POST['submit']) ) {
		if ( !is_admin() ) die("<div id=\"message\" class=\"error\" style=\"width:300px; font-weight:bold;\">No admin rights</div>");
		check_admin_referer('shieldpass-plugin-update'); // check nonce
		
		$form_publickey = mysql_real_escape_string($_POST['publickey']);
		$form_secretkey = mysql_real_escape_string($_POST['privatekey']);
		
		if ( ($form_publickey == "") && (get_sppublickey() == "No public key set!") ) { $errors[] = "The public key field was left empty!"; }
		elseif ( $form_publickey == "No public key set!" ) { $errors[] = "You didnt enter your Shieldpass public key!"; }
		elseif ( (!ctype_xdigit($form_publickey) ) && (get_sppublickey() == "No public key set!") ) { $errors[] = "There is a problem with your public key, is not Hex"; }
		elseif ( (strlen($form_publickey) < 64) && (get_sppublickey() == "No public key set!") ) { $errors[] = "There is a problem with your public key, less than 64 characters"; }
		
		if ( ($form_secretkey == "") && (get_spsecretkey() == "No secret key set!") ) { $errors[] = "The secret key field was left empty!"; }
		elseif ( $form_secretkey == "No secret key set!") { $errors[] = "You didnt enter your Shieldpass secret key!"; }
		elseif ( (!ctype_xdigit($form_secretkey)) && (get_spsecretkey() == "No secret key set!") ) { $errors[] = "There is a problem with your secret key, is not Hex"; }
		elseif ( (strlen($form_secretkey) < 64) && (get_spsecretkey() == "No secret key set!") ) { $errors[] = "There is a problem with your secret key, less than 64 characters"; }
		
		
		if ( isset($errors) ) {                          
			foreach ( $errors as $error ) {
			  echo("<div id=\"message\" class=\"error\" style=\"width:300px; font-weight:bold;\">$error</div>");
			}
		} elseif ( ($form_publickey != "") && ($form_secretkey != "") ) {	
			set_sppublickey($form_publickey);
			set_spsecretkey($form_secretkey);
		}
		
		if ( $_POST['nocarduser'] == '1' ) {
			update_option('shieldpass_allownocardusers', 'true');
		} elseif ( $_POST['nocarduser'] == '0' ) {
			$wpusers=$wpdb->get_results("SELECT wpuid FROM ".$wpdb->prefix."shieldpass;", ARRAY_A);

			foreach ( $wpusers as $wpuser ) {
				if ( get_userdata($wpuser['wpuid'])->user_level == 10 )
					$adminindb=true;
			}
			
			if ( $adminindb == true ) {
				update_option('shieldpass_allownocardusers', 'false');
			} else {
				echo("<div id=\"message\" class=\"error\" style=\"width:630px; font-weight:bold;\">Please associate at least one user with admin privileges with a Shieldpass card id.</div>");
			}
		}

        $spusers=$wpdb->get_results("SELECT MAX(id) FROM ".$wpdb->prefix."shieldpass;", ARRAY_A);
        for ( $i=1; $i <= $spusers[0]["MAX(id)"]; $i++ ) {
            if ( $_POST["del-".$i] == "delete" ) {
                $wpdb->query("DELETE FROM ".$wpdb->prefix."shieldpass WHERE id=$i;");
            }
        }
	
        if ( ($_POST["add_wpuser"] != '') && ($_POST["add_spuid"] != '') ) {
			$add_wpuser = htmlentities($_POST["add_wpuser"], ENT_QUOTES, 'UTF-8');
			$add_spuid = htmlentities($_POST["add_spuid"], ENT_QUOTES, 'UTF-8');
            $wpuid=get_userdatabylogin($add_wpuser)->ID;
            $wpusercount=$wpdb->get_results("SELECT COUNT(*) FROM ".$wpdb->prefix."shieldpass WHERE wpuid='$wpuid';", ARRAY_A);

            if ( $wpuid == false ) {
                echo("<div id=\"message\" class=\"error\" style=\"width:300px; font-weight:bold;\">User \"$wpuserclean\" doesn't exist.</div>");
            } elseif ( $wpusercount[0]['COUNT(*)'] > 0 ) {
                echo("<div id=\"message\" class=\"error\" style=\"width:450px; font-weight:bold;\">User \"$wpuserclean\" already associated with a Shieldpass card id.</div>");
            } else {
                $query=$wpdb->prepare("INSERT INTO ".$wpdb->prefix."shieldpass (wpuid,spuid) VALUES (%d,'%s');", mysql_real_escape_string($wpuid), mysql_real_escape_string($add_spuid));
                $wpdb->query($query);
            }
        }
	}
	

    ?><div class="wrap">
        <img src="../wp-content/plugins/shieldpass-two-factor-authentication/logo.jpg" alt="Shieldpass" style="margin-bottom: 10px" />
        <form action="" method="post">
		<?php
		if ( function_exists('wp_nonce_field') )
			wp_nonce_field('shieldpass-plugin-update');
			
		if ( get_sppublickey() == "No public key set!" ) {
			echo '<p><div>Public key:</div><input name="publickey" type="text" size="64" maxlength="64" value="'.get_sppublickey().'" /></p>';
		} else {
			$censoredpublickey = substr(get_sppublickey(), 0, 4).'************************************************************';
			echo '<p><div>Public key is currently set to: '.$censoredpublickey.'</div>Update: <input name="publickey" type="text" size="64" maxlength="64" value="" /></p>';
		}
		if ( get_spsecretkey() == "No secret key set!" ) {
			echo '<p><div>Secret key:</div><input name="privatekey" type="text" size="64" maxlength="64" value="'.get_spsecretkey().'" /></p>';
		} else {
			$censoredsecretkey = substr(get_spsecretkey(), 0, 4).'************************************************************';
			echo '<p><div>Secret key is currently set to: '.$censoredsecretkey.'</div>Update: <input name="privatekey" type="text" size="64" maxlength="64" value="" /></p>';
		}
		?>
            <p>
                <div>Allow users who do not have an associated ShieldPass card ID:</div>
                <?php 
                $ret = get_option('shieldpass_allownocardusers', 'true');
                if ( $ret == 'true' ) {
                    $yes = 'selected="selected"';
                    $no = '';
                } else {
                    $no = 'selected="selected"';
                    $yes = '';
                } ?>
                <select name="nocarduser" size="1">
                    <option <?php echo($yes);?> value="1">Yes</option>
                    <option <?php echo($no);?> value="0">No</option>
                </select>
            </p>
            <p>
                <table class="wp-list-table widefat fixed users">
                    <thead>
                        <th class="manage-column column-username sortable desc">WordPress username</th>
                        <th class="manage-column column-username sortable desc">ShieldPass card ID</th>
                        <th>Delete?</th>
                    </thead>
                    <?php
                    $sp_tablename=$wpdb->prefix."shieldpass";
                    $spusers=$wpdb->get_results("SELECT * FROM $sp_tablename;");
                    foreach ( $spusers as $spuser ) {
                        echo("<tr><th>".get_userdata($spuser->wpuid)->user_login."</th>\n");
                        echo("<th>$spuser->spuid</th>");
                        echo("<th><input type=\"checkbox\" name=\"del-$spuser->id\" value=\"delete\" /></th></tr>");
                    } ?>
                </table>
            </p>
            <p>
                <div ><b>Add User:</b></div><br />
                WordPress username: <input type="text" name="add_wpuser" />
                ShieldPass card ID: <input type="text" name="add_spuid" />
            </p>
			<p align="center">*get the ShieldPass card ID from your <a href="https://www.shieldpass.com/account.html" title="ShieldPass account page" target="_blank">www.shieldpass.com/account.html</a> client account page</p>
            <input name="submit" type="submit" value="Apply" />
        </form>
      </div>
	  <br><br><br>
	  <div ><b>*Note:</b> If you have enabled <strong>direct authentication</strong> in your ShieldPass admin panel, then you will need to manually set the "<strong>Return URL</strong>" field in the ShieldPass admin panel such that it points directly to shieldpassauth.php For example:</div>
	  <?php
	  $shieldpassauthpath=preg_replace("/wp-admin\/users\.php/", "wp-content/plugins/shieldpass-two-factor-authentication/shieldpassauth.php", $_SERVER['SCRIPT_NAME']);
		if ( $_SERVER['HTTPS'] == 'on' ) {
			echo "https://".$_SERVER['SERVER_NAME'].$shieldpassauthpath;
		} else {
			echo "http://".$_SERVER['SERVER_NAME'].$shieldpassauthpath;
		}
}

function shieldpass_adminpanel_init(){
    add_submenu_page('users.php',
                     'Shieldpass Configuration',
                     'Shieldpass Configuration',
                     'add_users', 'shieldpassconf',
                     'shieldpass_adminpanel');
}
add_action('admin_menu', 'shieldpass_adminpanel_init');

function shieldpass_access_denied($shake_codes){
    $shake_codes[] = 'sp_denied';
    return $shake_codes;
}
add_filter('shake_error_codes', 'shieldpass_access_denied');
?>