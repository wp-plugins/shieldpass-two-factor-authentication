<?php
/*    
 * This is a PHP library that handles calling the ShieldPass authentication server.
 * library version		2.0
 * copyright(c)2011 ShieldPass 
 * link 		https://shieldpass.com
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * You must generate new ShieldPass public and secret key pairs from your account page
 * alternatively you can use the printed secret key mailed with the access cards as your secret key. 
 */
 
 /*
 * Define the ShieldPass central authentication server URL's
 */
define("SHIELDPASS_API_SERVER", "http://www.shieldpass.com/api");
define("SHIELDPASS_API_SECURE_SERVER", "https://www.shieldpass.com/api");
define("SHIELDPASS_VERIFY_SERVER", "www.shieldpass.com");

//---------------AES 256 encryption---------------
	function urlsafe_b64encode($string) {
		$base64_data = base64_encode($string);
		return str_replace(array('+','/','='),array('-','_','.'),$base64_data);
	}

	function _shieldpass_aes_pad($data) {
        $length = strlen($data);
        if ($length % 16 == 0) return $data;
        $pad = 16 - ($length % 16);
        return str_pad($data, $length + $pad, chr($pad));
	}
	
	function _shieldpass_aes_encrypt($data,$ky) {
		$data=md5(mt_rand())._shieldpass_aes_pad($data);
		return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $ky, $data, MCRYPT_MODE_CBC, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
	}
	
	function shieldpass_encrypt($secretkey, $data) {
		if ($secretkey == "" || $secretkey == null) die ("To use ShieldPass you must use a secret key which is printed along with your access cards<br>you can also generate new keys online in your administration account");
		$ky = pack('H*', $secretkey);
		if (! function_exists("mcrypt_encrypt")) {
			$aes_php = new Crypt_AES_PHP();
			$aes_php->setKey($ky);
			return urlsafe_b64encode($aes_php->encrypt($data));
		}
		$cryptresponse = _shieldpass_aes_encrypt($data, $ky);
		return urlsafe_b64encode($cryptresponse);
	}
//---------------AES 256 decryption---------------
	function urlsafe_b64decode($string) {
	  $data = str_replace(array('-','_','.'),array('+','/','='),$string);
	  $mod4 = strlen($data) % 4;
	  if ($mod4) $data .= substr('====', $mod4);
	  return base64_decode($data);
	}

    function _shieldpass_aes_unpad($data) {
        $length = ord($data[strlen($data) - 1]);
        return substr($data, 0, -$length);
    }	
	
	function _shieldpass_aes_decrypt($ky,$data) {
		return mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $ky, $data, MCRYPT_MODE_CBC, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
	}
	
	function shieldpass_decrypt($secretkey, $encoded_response) {
		if ($secretkey == "" || $secretkey == null) die ("To use ShieldPass you must use a public and secret key you get from your administration account");
		$ky = pack('H*', $secretkey);
		$encoded_response = urlsafe_b64decode($encoded_response);
		if (!function_exists("mcrypt_encrypt")) {
			$aes_php = new Crypt_AES_PHP();
			$aes_php->setKey($ky);
			return substr(trim(_shieldpass_aes_unpad($aes_php->decrypt($encoded_response))),32);
		}
		$decryptresponse = _shieldpass_aes_decrypt($ky,$encoded_response);
		return substr(trim(_shieldpass_aes_unpad($decryptresponse)),32); 
	}

/**
 * Gets the challenge HTML (javascript and non-javascript version).
 * This is called from the browser, and the resulting ShieldPass HTML widget
 * is embedded within the HTML form it was called from.
 * @param string $publickey A public key for ShieldPass client
 * @param string $secretkey A secret key for ShieldPass client
 * @param string $cardid A encrypted identification value for a particular ShieldPass client access card
 * @param string $transid Encoded transaction authentication numbers
 * @param boolean $use_ssl(optional, default is true)
 * @return string - The HTML to be embedded in the user's form.
 */
function shieldpass_get_html($publickey, $secretkey, $cardid, $transid, $use_ssl = true) {
	if ($publickey == null || $publickey == '' || $secretkey == null || $secretkey == '') {
		die ("To use ShieldPass you must include your public and secret key from your account page");
	}
	if ($cardid == null || $cardid == '') {
		die ("To use ShieldPass you must reference a cardid code from your account page");
	}
	if (preg_match('/\D+/D',$transid)) {
		die ("To use ShieldPass your transaction id numbers must be from 0-9");
	}
	if ($use_ssl) {             
		$server = SHIELDPASS_API_SECURE_SERVER;
    } else {                
		$server = SHIELDPASS_API_SERVER;
    }        
	
		$crypt_cardid_js = shieldpass_encrypt($secretkey, $cardid.'|js|'.$transid.'|');
		$crypt_cardid_sp = shieldpass_encrypt($secretkey, $cardid.'|sp|'.$transid.'|');
        return '<script type="text/javascript" src="'.$server.'/challenge?k='.$publickey.'&c='.$crypt_cardid_js.'"></script>

	<noscript>
  		<a href="https://www.shieldpass.com/authenticate.html?k='.$publickey.'&c='.$crypt_cardid_sp.'"><input name="login" id="login" type="submit" value="direct login"/></a>
	</noscript>';
}

//-----------------check response-----------------------------------
/**
 * Encodes the given data into a query string format
 * @param $data - array of string elements to be encoded
 * @return string - encoded request
 */
function _shieldpass_qsencode($data) {
        $req = "";
        foreach ($data as $key => $value)
                $req .= $key.'='.urlencode(stripslashes($value)).'&';
        $req=substr($req,0,strlen($req)-1);
        return $req;
}
/**
 * Submits an HTTP POST to a shieldpass authentication server
 * @param string $host
 * @param string $path
 * @param array $data
 * @param int port
 * @return array response
 */
function _shieldpass_curl_http_post($host, $path, $data, $port = 80) { 
        $add_headers = array( 
            "Host: $host", 
        ); 
        $curl = curl_init( 'http://' . $host . ':' . $port . $path ); 
        curl_setopt( $curl, CURLOPT_POST, true ); 
        curl_setopt( $curl, CURLOPT_RETURNTRANSFER, true ); 
        curl_setopt( $curl, CURLOPT_CONNECTTIMEOUT, 10 ); 
        curl_setopt( $curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0 ); 
        curl_setopt( $curl, CURLOPT_USERAGENT, 'User-Agent: ShieldPass/2.0 (PHP; en-US)' ); 
        curl_setopt( $curl, CURLOPT_POSTFIELDS, $data ); 
        curl_setopt( $curl, CURLOPT_HEADER, true ); 
        curl_setopt( $curl, CURLOPT_HTTPHEADER, $add_headers ); 
        if ( isset( $_ENV['http_proxy'] ) && !empty ( $_ENV['http_proxy'] ) ) { 
            curl_setopt( $curl, CURLOPT_HTTPPROXYTUNNEL, true ); 
            curl_setopt( $curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP ); 
            curl_setopt( $curl, CURLOPT_PROXY, $_ENV['http_proxy'] );  // CURLOPT_PROXYUSERPWD as username:password needed? 
        } 
        $response = curl_exec( $curl ); 
        if ( $response === false ) die('Error connecting to ' . $host . '.'); 
        $response = explode("\r\n\r\n", $response, 2); 
        return $response; 
} 
/**
 * Alternative HTTP POST if curl not installed
 */
function _shieldpass_http_post($host, $path, $data, $port = 80) {
        $req = _shieldpass_qsencode($data);
        $http_request  = "POST $path HTTP/1.0\r\n";
        $http_request .= "Host: $host\r\n";
        $http_request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
        $http_request .= "Content-Length: ".strlen($req)."\r\n";
        $http_request .= "User-Agent: ShieldPass/2.0 (PHP; en-US)\r\n";
        $http_request .= "\r\n";
        $http_request .= $req;
        $response = '';
        if(false == ($fs = @fsockopen($host, $port, $errno, $errstr, 10))) {
                die('Could not open socket');
        }
        fwrite($fs, $http_request);
        while ( !feof($fs) )
                $response .= fgets($fs, 1160); // One TCP-IP packet
        fclose($fs);
        $response = explode("\r\n\r\n", $response, 2); // splits header[0] from body[1]
        return $response;
}
/**
 * A ShieldPassResponse is returned from shieldpass_check_answer()
 */
class ShieldPassResponse {
        var $is_valid;
        var $detail;
}
/**
 * Calls an HTTP POST function to verify if the user's response was correct
 * @param string $publickey
 * @param string $secretkey
 * @param string $cardid
 * @param string $response
 * @param array $extra_params an array of extra variables to post to the server
 * @return ShieldPassResponse
 */
function shieldpass_check_answer($publickey, $secretkey, $cardid, $response, $extra_params = array()) {
	if ($publickey == null || $publickey == '' || $secretkey == null || $secretkey == '') {
		die ("To use shieldpass you must get a set of keys from your account page");
	}
	if ($cardid == null || $cardid == '' || preg_match('/[^a-zA-Z0-9_.-]+/D', $cardid)) {
		die ("To use ShieldPass you must use a reference card id code from your account page");
	}
    if ($response == null || strlen($response) == 0) {
             $shieldpass_response = new ShieldPassResponse();
             $shieldpass_response->is_valid = false;
             $shieldpass_response->detail = '011\nInternal error';
             return $shieldpass_response;
    }
	
		$crypt_client_response = shieldpass_encrypt($secretkey,$response."|".$cardid."|".strtr(serialize($_SERVER),'|','-')."|2.0|PHP|en-US");
	if (function_exists('curl_init')) {	
        $server_response = _shieldpass_curl_http_post(SHIELDPASS_VERIFY_SERVER, "/api/verify/index.html",
                                          array(
                                                'publickey' => $publickey,
                                                'client_response' => $crypt_client_response
                                                ) + $extra_params
                                          );
	} else {
        $server_response = _shieldpass_http_post(SHIELDPASS_VERIFY_SERVER, "/api/verify/index.html",
                                          array(
                                                'publickey' => $publickey,
                                                'client_response' => $crypt_client_response
                                                ) + $extra_params
                                          );
	}	
		$server_response_decrypt = shieldpass_decrypt($secretkey, $server_response[1]);
        $answers = explode("\n", $server_response_decrypt);
/**
 * Details of the shieldpass authentication are returned in $answers[1]
 *  numeric -   Text Response
 *		000 -	Passcode correct
 * 		001	-	Passcode incorrect
 *		002	-	UID incorrect
 *		003	-	Password incorrect
 *		004	-	Timed lockout in effect (message indicates whether this was	a result of repeated UID or password failure)
 *		005	-	IP blocked
 *		006	-	Disabled user ID
 *		007	-	Challenge expired
 *		008	-	Authentication attempt limit exceeded (user did not solve challenge and is informed that they will have to solve an additional challenge)
 *		009 -	Authentication attempt limit exceeded (user was successful but is required to solve additional challenge)
 *		010 -	Server error
 *		011 -	Internal error
 */
        $shieldpass_response = new ShieldPassResponse();
        if (trim ($answers[0]) == 'true') {
                $shieldpass_response->is_valid = true;
                $shieldpass_response->detail = $answers[1];
        } else {
                $shieldpass_response->is_valid = false;
                $shieldpass_response->detail = $answers[1];
        }
	
        return $shieldpass_response;
}

/**
 * Pure-PHP implementation of AES automatically used by ShieldPass when mcrypt is not installed on a client server.
 * Kindly donated to the Shieldpass project by Jim Wiggington <terrafrost@php.net> and then compressed by Shieldpass for AES use in CBC mode only
 * @original author  Jim Wigginton <terrafrost@php.net>
 * @compacted by     Matthew Walker 
 * @copyright  	     MMVIII Jim Wigginton
 * @version    	     Shieldpass AES in CBC mode only
 * @original link    http://phpseclib.sourceforge.net
 * Please note that this Shieldpass AES PHP version is compressed for the Shieldpass library file while the original phpseclib 
 * written by Jim Wiggington contains a much more expansive version complete with the many other modes of AES operation such as CTR,ECB,CFB,OFB
 * PHP versions 4 and 5
 * Encrypt / decrypt using the Code Book Chaining mode.
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
 * Comments have been removed for the sake of file size while the originals can be found at http://phpseclib.sourceforge.net
 * {@internal The variable names are the same as those in 
 * {@link http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf#page=10 fips-197.pdf#page=10}.}}
 */

class Crypt_AES_PHP {
    var $mode;
    var $key = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    var $iv = '';
    var $encryptIV = '';
    var $decryptIV = '';
    var $continuousBuffer = false;
    var $padding = true;
    var $changed = true;
    var $explicit_key_length = false;
    var $w;
    var $dw;
    var $block_size = 16;
    var $Nb = 4;
    var $key_size = 16;
    var $Nk = 4;
    var $Nr;
    var $c;
    var $t0;
    var $t1;
    var $t2;
    var $t3;
    var $dt0;
    var $dt1;
    var $dt2;
    var $dt3;
    var $paddable = false;

    function Crypt_AES_PHP()    {
			$this->mode = CRYPT_AES_MODE_CBC;
			$this->paddable = true;
					
            $t3 = &$this->t3;
            $t2 = &$this->t2;
            $t1 = &$this->t1;
            $t0 = &$this->t0;

            $dt3 = &$this->dt3;
            $dt2 = &$this->dt2;
            $dt1 = &$this->dt1;
            $dt0 = &$this->dt0;

            // according to <http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf#page=19> (section 5.2.1), 
            // precomputed tables can be used in the mixColumns phase.  in that example, they're assigned t0...t3, so
            // those are the names we'll use.
            $t3 = array(
                0x6363A5C6, 0x7C7C84F8, 0x777799EE, 0x7B7B8DF6, 0xF2F20DFF, 0x6B6BBDD6, 0x6F6FB1DE, 0xC5C55491, 
                0x30305060, 0x01010302, 0x6767A9CE, 0x2B2B7D56, 0xFEFE19E7, 0xD7D762B5, 0xABABE64D, 0x76769AEC, 
                0xCACA458F, 0x82829D1F, 0xC9C94089, 0x7D7D87FA, 0xFAFA15EF, 0x5959EBB2, 0x4747C98E, 0xF0F00BFB, 
                0xADADEC41, 0xD4D467B3, 0xA2A2FD5F, 0xAFAFEA45, 0x9C9CBF23, 0xA4A4F753, 0x727296E4, 0xC0C05B9B, 
                0xB7B7C275, 0xFDFD1CE1, 0x9393AE3D, 0x26266A4C, 0x36365A6C, 0x3F3F417E, 0xF7F702F5, 0xCCCC4F83, 
                0x34345C68, 0xA5A5F451, 0xE5E534D1, 0xF1F108F9, 0x717193E2, 0xD8D873AB, 0x31315362, 0x15153F2A, 
                0x04040C08, 0xC7C75295, 0x23236546, 0xC3C35E9D, 0x18182830, 0x9696A137, 0x05050F0A, 0x9A9AB52F,
                0x0707090E, 0x12123624, 0x80809B1B, 0xE2E23DDF, 0xEBEB26CD, 0x2727694E, 0xB2B2CD7F, 0x75759FEA, 
                0x09091B12, 0x83839E1D, 0x2C2C7458, 0x1A1A2E34, 0x1B1B2D36, 0x6E6EB2DC, 0x5A5AEEB4, 0xA0A0FB5B, 
                0x5252F6A4, 0x3B3B4D76, 0xD6D661B7, 0xB3B3CE7D, 0x29297B52, 0xE3E33EDD, 0x2F2F715E, 0x84849713, 
                0x5353F5A6, 0xD1D168B9, 0x00000000, 0xEDED2CC1, 0x20206040, 0xFCFC1FE3, 0xB1B1C879, 0x5B5BEDB6, 
                0x6A6ABED4, 0xCBCB468D, 0xBEBED967, 0x39394B72, 0x4A4ADE94, 0x4C4CD498, 0x5858E8B0, 0xCFCF4A85, 
                0xD0D06BBB, 0xEFEF2AC5, 0xAAAAE54F, 0xFBFB16ED, 0x4343C586, 0x4D4DD79A, 0x33335566, 0x85859411, 
                0x4545CF8A, 0xF9F910E9, 0x02020604, 0x7F7F81FE, 0x5050F0A0, 0x3C3C4478, 0x9F9FBA25, 0xA8A8E34B, 
                0x5151F3A2, 0xA3A3FE5D, 0x4040C080, 0x8F8F8A05, 0x9292AD3F, 0x9D9DBC21, 0x38384870, 0xF5F504F1, 
                0xBCBCDF63, 0xB6B6C177, 0xDADA75AF, 0x21216342, 0x10103020, 0xFFFF1AE5, 0xF3F30EFD, 0xD2D26DBF, 
                0xCDCD4C81, 0x0C0C1418, 0x13133526, 0xECEC2FC3, 0x5F5FE1BE, 0x9797A235, 0x4444CC88, 0x1717392E, 
                0xC4C45793, 0xA7A7F255, 0x7E7E82FC, 0x3D3D477A, 0x6464ACC8, 0x5D5DE7BA, 0x19192B32, 0x737395E6, 
                0x6060A0C0, 0x81819819, 0x4F4FD19E, 0xDCDC7FA3, 0x22226644, 0x2A2A7E54, 0x9090AB3B, 0x8888830B, 
                0x4646CA8C, 0xEEEE29C7, 0xB8B8D36B, 0x14143C28, 0xDEDE79A7, 0x5E5EE2BC, 0x0B0B1D16, 0xDBDB76AD, 
                0xE0E03BDB, 0x32325664, 0x3A3A4E74, 0x0A0A1E14, 0x4949DB92, 0x06060A0C, 0x24246C48, 0x5C5CE4B8, 
                0xC2C25D9F, 0xD3D36EBD, 0xACACEF43, 0x6262A6C4, 0x9191A839, 0x9595A431, 0xE4E437D3, 0x79798BF2, 
                0xE7E732D5, 0xC8C8438B, 0x3737596E, 0x6D6DB7DA, 0x8D8D8C01, 0xD5D564B1, 0x4E4ED29C, 0xA9A9E049, 
                0x6C6CB4D8, 0x5656FAAC, 0xF4F407F3, 0xEAEA25CF, 0x6565AFCA, 0x7A7A8EF4, 0xAEAEE947, 0x08081810, 
                0xBABAD56F, 0x787888F0, 0x25256F4A, 0x2E2E725C, 0x1C1C2438, 0xA6A6F157, 0xB4B4C773, 0xC6C65197, 
                0xE8E823CB, 0xDDDD7CA1, 0x74749CE8, 0x1F1F213E, 0x4B4BDD96, 0xBDBDDC61, 0x8B8B860D, 0x8A8A850F, 
                0x707090E0, 0x3E3E427C, 0xB5B5C471, 0x6666AACC, 0x4848D890, 0x03030506, 0xF6F601F7, 0x0E0E121C, 
                0x6161A3C2, 0x35355F6A, 0x5757F9AE, 0xB9B9D069, 0x86869117, 0xC1C15899, 0x1D1D273A, 0x9E9EB927, 
                0xE1E138D9, 0xF8F813EB, 0x9898B32B, 0x11113322, 0x6969BBD2, 0xD9D970A9, 0x8E8E8907, 0x9494A733, 
                0x9B9BB62D, 0x1E1E223C, 0x87879215, 0xE9E920C9, 0xCECE4987, 0x5555FFAA, 0x28287850, 0xDFDF7AA5, 
                0x8C8C8F03, 0xA1A1F859, 0x89898009, 0x0D0D171A, 0xBFBFDA65, 0xE6E631D7, 0x4242C684, 0x6868B8D0, 
                0x4141C382, 0x9999B029, 0x2D2D775A, 0x0F0F111E, 0xB0B0CB7B, 0x5454FCA8, 0xBBBBD66D, 0x16163A2C
            );

            $dt3 = array(
                0xF4A75051, 0x4165537E, 0x17A4C31A, 0x275E963A, 0xAB6BCB3B, 0x9D45F11F, 0xFA58ABAC, 0xE303934B, 
                0x30FA5520, 0x766DF6AD, 0xCC769188, 0x024C25F5, 0xE5D7FC4F, 0x2ACBD7C5, 0x35448026, 0x62A38FB5, 
                0xB15A49DE, 0xBA1B6725, 0xEA0E9845, 0xFEC0E15D, 0x2F7502C3, 0x4CF01281, 0x4697A38D, 0xD3F9C66B, 
                0x8F5FE703, 0x929C9515, 0x6D7AEBBF, 0x5259DA95, 0xBE832DD4, 0x7421D358, 0xE0692949, 0xC9C8448E, 
                0xC2896A75, 0x8E7978F4, 0x583E6B99, 0xB971DD27, 0xE14FB6BE, 0x88AD17F0, 0x20AC66C9, 0xCE3AB47D, 
                0xDF4A1863, 0x1A3182E5, 0x51336097, 0x537F4562, 0x6477E0B1, 0x6BAE84BB, 0x81A01CFE, 0x082B94F9, 
                0x48685870, 0x45FD198F, 0xDE6C8794, 0x7BF8B752, 0x73D323AB, 0x4B02E272, 0x1F8F57E3, 0x55AB2A66, 
                0xEB2807B2, 0xB5C2032F, 0xC57B9A86, 0x3708A5D3, 0x2887F230, 0xBFA5B223, 0x036ABA02, 0x16825CED, 
                0xCF1C2B8A, 0x79B492A7, 0x07F2F0F3, 0x69E2A14E, 0xDAF4CD65, 0x05BED506, 0x34621FD1, 0xA6FE8AC4, 
                0x2E539D34, 0xF355A0A2, 0x8AE13205, 0xF6EB75A4, 0x83EC390B, 0x60EFAA40, 0x719F065E, 0x6E1051BD, 
                0x218AF93E, 0xDD063D96, 0x3E05AEDD, 0xE6BD464D, 0x548DB591, 0xC45D0571, 0x06D46F04, 0x5015FF60, 
                0x98FB2419, 0xBDE997D6, 0x4043CC89, 0xD99E7767, 0xE842BDB0, 0x898B8807, 0x195B38E7, 0xC8EEDB79, 
                0x7C0A47A1, 0x420FE97C, 0x841EC9F8, 0x00000000, 0x80868309, 0x2BED4832, 0x1170AC1E, 0x5A724E6C, 
                0x0EFFFBFD, 0x8538560F, 0xAED51E3D, 0x2D392736, 0x0FD9640A, 0x5CA62168, 0x5B54D19B, 0x362E3A24, 
                0x0A67B10C, 0x57E70F93, 0xEE96D2B4, 0x9B919E1B, 0xC0C54F80, 0xDC20A261, 0x774B695A, 0x121A161C, 
                0x93BA0AE2, 0xA02AE5C0, 0x22E0433C, 0x1B171D12, 0x090D0B0E, 0x8BC7ADF2, 0xB6A8B92D, 0x1EA9C814, 
                0xF1198557, 0x75074CAF, 0x99DDBBEE, 0x7F60FDA3, 0x01269FF7, 0x72F5BC5C, 0x663BC544, 0xFB7E345B, 
                0x4329768B, 0x23C6DCCB, 0xEDFC68B6, 0xE4F163B8, 0x31DCCAD7, 0x63851042, 0x97224013, 0xC6112084, 
                0x4A247D85, 0xBB3DF8D2, 0xF93211AE, 0x29A16DC7, 0x9E2F4B1D, 0xB230F3DC, 0x8652EC0D, 0xC1E3D077, 
                0xB3166C2B, 0x70B999A9, 0x9448FA11, 0xE9642247, 0xFC8CC4A8, 0xF03F1AA0, 0x7D2CD856, 0x3390EF22, 
                0x494EC787, 0x38D1C1D9, 0xCAA2FE8C, 0xD40B3698, 0xF581CFA6, 0x7ADE28A5, 0xB78E26DA, 0xADBFA43F, 
                0x3A9DE42C, 0x78920D50, 0x5FCC9B6A, 0x7E466254, 0x8D13C2F6, 0xD8B8E890, 0x39F75E2E, 0xC3AFF582, 
                0x5D80BE9F, 0xD0937C69, 0xD52DA96F, 0x2512B3CF, 0xAC993BC8, 0x187DA710, 0x9C636EE8, 0x3BBB7BDB, 
                0x267809CD, 0x5918F46E, 0x9AB701EC, 0x4F9AA883, 0x956E65E6, 0xFFE67EAA, 0xBCCF0821, 0x15E8E6EF, 
                0xE79BD9BA, 0x6F36CE4A, 0x9F09D4EA, 0xB07CD629, 0xA4B2AF31, 0x3F23312A, 0xA59430C6, 0xA266C035, 
                0x4EBC3774, 0x82CAA6FC, 0x90D0B0E0, 0xA7D81533, 0x04984AF1, 0xECDAF741, 0xCD500E7F, 0x91F62F17, 
                0x4DD68D76, 0xEFB04D43, 0xAA4D54CC, 0x9604DFE4, 0xD1B5E39E, 0x6A881B4C, 0x2C1FB8C1, 0x65517F46, 
                0x5EEA049D, 0x8C355D01, 0x877473FA, 0x0B412EFB, 0x671D5AB3, 0xDBD25292, 0x105633E9, 0xD647136D, 
                0xD7618C9A, 0xA10C7A37, 0xF8148E59, 0x133C89EB, 0xA927EECE, 0x61C935B7, 0x1CE5EDE1, 0x47B13C7A, 
                0xD2DF599C, 0xF2733F55, 0x14CE7918, 0xC737BF73, 0xF7CDEA53, 0xFDAA5B5F, 0x3D6F14DF, 0x44DB8678, 
                0xAFF381CA, 0x68C43EB9, 0x24342C38, 0xA3405FC2, 0x1DC37216, 0xE2250CBC, 0x3C498B28, 0x0D9541FF, 
                0xA8017139, 0x0CB3DE08, 0xB4E49CD8, 0x56C19064, 0xCB84617B, 0x32B670D5, 0x6C5C7448, 0xB85742D0
            );

            for ($i = 0; $i < 256; $i++) {
                $t2[$i <<  8] = (($t3[$i] <<  8) & 0xFFFFFF00) | (($t3[$i] >> 24) & 0x000000FF);
                $t1[$i << 16] = (($t3[$i] << 16) & 0xFFFF0000) | (($t3[$i] >> 16) & 0x0000FFFF);
                $t0[$i << 24] = (($t3[$i] << 24) & 0xFF000000) | (($t3[$i] >>  8) & 0x00FFFFFF);

                $dt2[$i <<  8] = (($this->dt3[$i] <<  8) & 0xFFFFFF00) | (($dt3[$i] >> 24) & 0x000000FF);
                $dt1[$i << 16] = (($this->dt3[$i] << 16) & 0xFFFF0000) | (($dt3[$i] >> 16) & 0x0000FFFF);
                $dt0[$i << 24] = (($this->dt3[$i] << 24) & 0xFF000000) | (($dt3[$i] >>  8) & 0x00FFFFFF);
            }
    }

    function setKey($key)    {
        $this->key = $key;
        $this->changed = true;
    }

    function setKeyLength($length)    {
        $length >>= 5;
        if ($length > 8) {
            $length = 8;
        } else if ($length < 4) {
            $length = 4;
        }
        $this->Nk = $length;
        $this->key_size = $length << 2;

        $this->explicit_key_length = true;
        $this->changed = true;
    }

    function setBlockLength($length)    {
        return;
    }
	
    function encrypt($plaintext) {

        $this->_setup();
        if ($this->paddable) {
            $plaintext = $this->_pad($plaintext);
        }

        $block_size = $this->block_size;
        $buffer = &$this->enbuffer;
        $continuousBuffer = $this->continuousBuffer;
        $ciphertext = '';
             // CRYPT_AES_MODE_CBC:
                $xor = $this->encryptIV;
                for ($i = 0; $i < strlen($plaintext); $i+=$block_size) {
                    $block = substr($plaintext, $i, $block_size);
                    $block = $this->_encryptBlock($block ^ $xor);
                    $xor = $block;
                    $ciphertext.= $block;
                }
                if ($this->continuousBuffer) {
                    $this->encryptIV = $xor;
                }
        return $ciphertext;
    }

    function decrypt($ciphertext)   {
        $this->_setup();
        if ($this->paddable) {
            // we pad with chr(0) since that's what mcrypt_generic does.  to quote from http://php.net/function.mcrypt-generic :
            // "The data is padded with "\0" to make sure the length of the data is n * blocksize."
            $ciphertext = str_pad($ciphertext, strlen($ciphertext) + ($this->block_size - strlen($ciphertext) % $this->block_size) % $this->block_size, chr(0));
        }

        $block_size = $this->block_size;
        $buffer = &$this->debuffer;
        $continuousBuffer = $this->continuousBuffer;
        $plaintext = '';
             // CRYPT_AES_MODE_CBC:
                $xor = $this->decryptIV;
                for ($i = 0; $i < strlen($ciphertext); $i+=$block_size) {
                    $block = substr($ciphertext, $i, $block_size);
                    $plaintext.= $this->_decryptBlock($block) ^ $xor;
                    $xor = $block;
                }
                if ($this->continuousBuffer) {
                    $this->decryptIV = $xor;
                }

        return $this->paddable ? $this->_unpad($plaintext) : $plaintext;
    }

    function _encryptBlock($in)    {
        $state = unpack('N*word', $in);

        $Nr = $this->Nr;
        $w = $this->w;
        $t0 = $this->t0;
        $t1 = $this->t1;
        $t2 = $this->t2;
        $t3 = $this->t3;

        // addRoundKey and reindex $state
        $state = array(
            $state['word1'] ^ $w[0][0],
            $state['word2'] ^ $w[0][1],
            $state['word3'] ^ $w[0][2],
            $state['word4'] ^ $w[0][3]
        );

        // shiftRows + subWord + mixColumns + addRoundKey
        for ($round = 1; $round < $this->Nr; $round++) {
            $state = array(
                $t0[$state[0] & 0xFF000000] ^ $t1[$state[1] & 0x00FF0000] ^ $t2[$state[2] & 0x0000FF00] ^ $t3[$state[3] & 0x000000FF] ^ $w[$round][0],
                $t0[$state[1] & 0xFF000000] ^ $t1[$state[2] & 0x00FF0000] ^ $t2[$state[3] & 0x0000FF00] ^ $t3[$state[0] & 0x000000FF] ^ $w[$round][1],
                $t0[$state[2] & 0xFF000000] ^ $t1[$state[3] & 0x00FF0000] ^ $t2[$state[0] & 0x0000FF00] ^ $t3[$state[1] & 0x000000FF] ^ $w[$round][2],
                $t0[$state[3] & 0xFF000000] ^ $t1[$state[0] & 0x00FF0000] ^ $t2[$state[1] & 0x0000FF00] ^ $t3[$state[2] & 0x000000FF] ^ $w[$round][3]
            );

        }

        // subWord
        $state = array(
            $this->_subWord($state[0]),
            $this->_subWord($state[1]),
            $this->_subWord($state[2]),
            $this->_subWord($state[3])
        );

        // shiftRows + addRoundKey
        $state = array(
            ($state[0] & 0xFF000000) ^ ($state[1] & 0x00FF0000) ^ ($state[2] & 0x0000FF00) ^ ($state[3] & 0x000000FF) ^ $this->w[$this->Nr][0],
            ($state[1] & 0xFF000000) ^ ($state[2] & 0x00FF0000) ^ ($state[3] & 0x0000FF00) ^ ($state[0] & 0x000000FF) ^ $this->w[$this->Nr][1],
            ($state[2] & 0xFF000000) ^ ($state[3] & 0x00FF0000) ^ ($state[0] & 0x0000FF00) ^ ($state[1] & 0x000000FF) ^ $this->w[$this->Nr][2],
            ($state[3] & 0xFF000000) ^ ($state[0] & 0x00FF0000) ^ ($state[1] & 0x0000FF00) ^ ($state[2] & 0x000000FF) ^ $this->w[$this->Nr][3]
        );

        return pack('N*', $state[0], $state[1], $state[2], $state[3]);
    }

    function _decryptBlock($in)    {
        $state = unpack('N*word', $in);

        $Nr = $this->Nr;
        $dw = $this->dw;
        $dt0 = $this->dt0;
        $dt1 = $this->dt1;
        $dt2 = $this->dt2;
        $dt3 = $this->dt3;

        // addRoundKey and reindex $state
        $state = array(
            $state['word1'] ^ $dw[$this->Nr][0],
            $state['word2'] ^ $dw[$this->Nr][1],
            $state['word3'] ^ $dw[$this->Nr][2],
            $state['word4'] ^ $dw[$this->Nr][3]
        );

        // invShiftRows + invSubBytes + invMixColumns + addRoundKey
        for ($round = $this->Nr - 1; $round > 0; $round--) {
            $state = array(
                $dt0[$state[0] & 0xFF000000] ^ $dt1[$state[3] & 0x00FF0000] ^ $dt2[$state[2] & 0x0000FF00] ^ $dt3[$state[1] & 0x000000FF] ^ $dw[$round][0],
                $dt0[$state[1] & 0xFF000000] ^ $dt1[$state[0] & 0x00FF0000] ^ $dt2[$state[3] & 0x0000FF00] ^ $dt3[$state[2] & 0x000000FF] ^ $dw[$round][1],
                $dt0[$state[2] & 0xFF000000] ^ $dt1[$state[1] & 0x00FF0000] ^ $dt2[$state[0] & 0x0000FF00] ^ $dt3[$state[3] & 0x000000FF] ^ $dw[$round][2],
                $dt0[$state[3] & 0xFF000000] ^ $dt1[$state[2] & 0x00FF0000] ^ $dt2[$state[1] & 0x0000FF00] ^ $dt3[$state[0] & 0x000000FF] ^ $dw[$round][3]
            );
        }

        // invShiftRows + invSubWord + addRoundKey
        $state = array(
            $this->_invSubWord(($state[0] & 0xFF000000) ^ ($state[3] & 0x00FF0000) ^ ($state[2] & 0x0000FF00) ^ ($state[1] & 0x000000FF)) ^ $dw[0][0],
            $this->_invSubWord(($state[1] & 0xFF000000) ^ ($state[0] & 0x00FF0000) ^ ($state[3] & 0x0000FF00) ^ ($state[2] & 0x000000FF)) ^ $dw[0][1],
            $this->_invSubWord(($state[2] & 0xFF000000) ^ ($state[1] & 0x00FF0000) ^ ($state[0] & 0x0000FF00) ^ ($state[3] & 0x000000FF)) ^ $dw[0][2],
            $this->_invSubWord(($state[3] & 0xFF000000) ^ ($state[2] & 0x00FF0000) ^ ($state[1] & 0x0000FF00) ^ ($state[0] & 0x000000FF)) ^ $dw[0][3]
        );

        return pack('N*', $state[0], $state[1], $state[2], $state[3]);
    }

    function _setup()    {
        // Each number in $rcon is equal to the previous number multiplied by two in Rijndael's finite field.
        // See http://en.wikipedia.org/wiki/Finite_field_arithmetic#Multiplicative_inverse
        static $rcon = array(0,
            0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
            0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000,
            0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000,
            0x2F000000, 0x5E000000, 0xBC000000, 0x63000000, 0xC6000000,
            0x97000000, 0x35000000, 0x6A000000, 0xD4000000, 0xB3000000,
            0x7D000000, 0xFA000000, 0xEF000000, 0xC5000000, 0x91000000
        );

        if (!$this->changed) {
            return;
        }

        if (!$this->explicit_key_length) {
            // we do >> 2, here, and not >> 5, as we do above, since strlen($this->key) tells us the number of bytes - not bits
            $length = strlen($this->key) >> 2;
            if ($length > 8) {
                $length = 8;
            } else if ($length < 4) {
                $length = 4;
            }
            $this->Nk = $length;
            $this->key_size = $length << 2;
        }

        $this->key = str_pad(substr($this->key, 0, $this->key_size), $this->key_size, chr(0));
        $this->encryptIV = $this->decryptIV = $this->iv = str_pad(substr($this->iv, 0, $this->block_size), $this->block_size, chr(0));

        // see Rijndael-ammended.pdf#page=44
        $this->Nr = max($this->Nk, $this->Nb) + 6;

        // shift offsets for Nb = 5, 7 are defined in Rijndael-ammended.pdf#page=44,
        //     "Table 8: Shift offsets in Shiftrow for the alternative block lengths"
        // shift offsets for Nb = 4, 6, 8 are defined in Rijndael-ammended.pdf#page=14,
        //     "Table 2: Shift offsets for different block lengths"
        switch ($this->Nb) {
            case 4:
            case 5:
            case 6:
                $this->c = array(0, 1, 2, 3);
                break;
            case 7:
                $this->c = array(0, 1, 2, 4);
                break;
            case 8:
                $this->c = array(0, 1, 3, 4);
        }

        $key = $this->key;

        $w = array_values(unpack('N*words', $key));

        $length = $this->Nb * ($this->Nr + 1);
        for ($i = $this->Nk; $i < $length; $i++) {
            $temp = $w[$i - 1];
            if ($i % $this->Nk == 0) {
                // according to <http://php.net/language.types.integer>, "the size of an integer is platform-dependent".
                // on a 32-bit machine, it's 32-bits, and on a 64-bit machine, it's 64-bits. on a 32-bit machine,
                // 0xFFFFFFFF << 8 == 0xFFFFFF00, but on a 64-bit machine, it equals 0xFFFFFFFF00. as such, doing 'and'
                // with 0xFFFFFFFF (or 0xFFFFFF00) on a 32-bit machine is unnecessary, but on a 64-bit machine, it is.
                $temp = (($temp << 8) & 0xFFFFFF00) | (($temp >> 24) & 0x000000FF); // rotWord
                $temp = $this->_subWord($temp) ^ $rcon[$i / $this->Nk];
            } else if ($this->Nk > 6 && $i % $this->Nk == 4) {
                $temp = $this->_subWord($temp);
            }
            $w[$i] = $w[$i - $this->Nk] ^ $temp;
        }
        // convert the key schedule from a vector of $Nb * ($Nr + 1) length to a matrix with $Nr + 1 rows and $Nb columns
        // and generate the inverse key schedule.  more specifically,
        // according to <http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf#page=23> (section 5.3.3), 
        // "The key expansion for the Inverse Cipher is defined as follows:
        //        1. Apply the Key Expansion.
        //        2. Apply InvMixColumn to all Round Keys except the first and the last one."
        // also, see fips-197.pdf#page=27, "5.3.5 Equivalent Inverse Cipher"
        $temp = array();
        for ($i = $row = $col = 0; $i < $length; $i++, $col++) {
            if ($col == $this->Nb) {
                if ($row == 0) {
                    $this->dw[0] = $this->w[0];
                } else {
                    // subWord + invMixColumn + invSubWord = invMixColumn
                    $j = 0;
                    while ($j < $this->Nb) {
                        $dw = $this->_subWord($this->w[$row][$j]);
                        $temp[$j] = $this->dt0[$dw & 0xFF000000] ^ 
                                    $this->dt1[$dw & 0x00FF0000] ^ 
                                    $this->dt2[$dw & 0x0000FF00] ^ 
                                    $this->dt3[$dw & 0x000000FF];
                        $j++;
                    }
                    $this->dw[$row] = $temp;
                }

                $col = 0;
                $row++;
            }
            $this->w[$row][$col] = $w[$i];
        }

        $this->dw[$row] = $this->w[$row];

        $this->changed = false;
    }

    // Performs S-Box substitutions
    function _subWord($word)    {
        static $sbox0, $sbox1, $sbox2, $sbox3;

        if (empty($sbox0)) {
            $sbox0 = array(
                0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            );

            $sbox1 = array();
            $sbox2 = array();
            $sbox3 = array();

            for ($i = 0; $i < 256; $i++) {
                $sbox1[$i <<  8] = $sbox0[$i] <<  8;
                $sbox2[$i << 16] = $sbox0[$i] << 16;
                $sbox3[$i << 24] = $sbox0[$i] << 24;
            }
        }

        return $sbox0[$word & 0x000000FF] | 
               $sbox1[$word & 0x0000FF00] | 
               $sbox2[$word & 0x00FF0000] | 
               $sbox3[$word & 0xFF000000];
    }

    // Performs inverse S-Box substitutions
    function _invSubWord($word)    {
        static $sbox0, $sbox1, $sbox2, $sbox3;

        if (empty($sbox0)) {
            $sbox0 = array(
                0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
            );

            $sbox1 = array();
            $sbox2 = array();
            $sbox3 = array();

            for ($i = 0; $i < 256; $i++) {
                $sbox1[$i <<  8] = $sbox0[$i] <<  8;
                $sbox2[$i << 16] = $sbox0[$i] << 16;
                $sbox3[$i << 24] = $sbox0[$i] << 24;
            }
        }

        return $sbox0[$word & 0x000000FF] | 
               $sbox1[$word & 0x0000FF00] | 
               $sbox2[$word & 0x00FF0000] | 
               $sbox3[$word & 0xFF000000];
    }

    function enablePadding()    {
        $this->padding = true;
    }

    function disablePadding()    {
        $this->padding = false;
    }
	
    function _pad($text)    {
        $length = strlen($text);
        if (!$this->padding) {
            if ($length % $this->block_size == 0) {
                return $text;
            } else {
                user_error("The plaintext's length ($length) is not a multiple of the block size ({$this->block_size})", E_USER_NOTICE);
                $this->padding = true;
            }
        }

        $pad = $this->block_size - ($length % $this->block_size);

        return str_pad($text, $length + $pad, chr($pad));
    }

    function _unpad($text)    {
        if (!$this->padding) {
            return $text;
        }

        $length = ord($text[strlen($text) - 1]);

        if (!$length || $length > $this->block_size) {
            return false;
        }

        return substr($text, 0, -$length);
    }

    function enableContinuousBuffer()    {
        $this->continuousBuffer = true;
    }
	
    function disableContinuousBuffer()    {
        $this->continuousBuffer = false;
        $this->encryptIV = $this->iv;
        $this->decryptIV = $this->iv;
    }

    function _string_shift(&$string, $index = 1)    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);
        return $substr;
    }
}
?>