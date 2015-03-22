<?php
/**
 * Created by PhpStorm.
 * User: davidkryzaniak
 * Date: 22/03/15
 * Time: 11:53
 */

namespace davidkryzaniak\MissyElloittPHP;


class crypto {

	private $cypher;
	private $mode;

	/**
	 * Constructor
	 *
	 * @todo allow for key here, so you don't have to supply it for each decrypt/encrypt
	 *
	 * @param string $cypher    The MCRYPT cypher menthod you'd like to use. default: MCRYPT_RIJNDAEL_256
	 * @param string $mode      The MCRYPT method you'd like to use. default: MCRYPT_MODE_ECB
	 */
	public function __construct($cypher = '',$mode = '')
	{
		$this->cypher = ($cypher != '' ? $cypher : MCRYPT_RIJNDAEL_256);
		$this->mode = ($mode != '' ? $mode : MCRYPT_MODE_ECB);
	}

	/**
	 * Encrypt a message
	 *
	 * @param string $unencryptedString     Your clear text message
	 * @param string $key                   The string you'd like to encrypt with
	 *
	 * @return string                       The encrypted string
	 * @throws Exception    YOU'RE DOING IT WRONG
	 */
	public function encrypt($unencryptedString,$key)
	{
		$youGottaBigString = (is_string($unencryptedString));
		$itsWorthIt = (strlen($unencryptedString) > 0);

		if($youGottaBigString && $itsWorthIt) { //Let's encrypt it!

			//We're really going to encrypt this first...
			$unencryptedString = $this->_actuallyEncrypt($unencryptedString,$key);
			$encrypted = [];

			//foreach char
			foreach(str_split($unencryptedString) as $char){
				$value = unpack('H*', $char);
				$value = base_convert($value[1], 16, 2);
				$value = $this->_flip($value);              //Flip it
				$value = $this->_andReverse($value);        //Reverse it
				$encrypted[] = $value;
			}

			return implode(',',$encrypted); //hate that I have to do this... Maybe there's a better way? //@TODO Fix this?

		}else{
			//nope.
			throw new \Exception("Yeah, you ain't ahead of the game.");
		}

	}

	/**
	 * Decrypt a string
	 *
	 * @param string $encryptedString       Your encrypted string
	 * @param string $key                   The key you used to encrypt the message
	 *
	 * @return string                       Clear text message
	 * @throws Exception        YOU'RE DOING IT WRONG
	 */
	public function decrypt($encryptedString,$key)
	{
		$youGottaBigString = (is_string($encryptedString));
		$encrypted = @explode(',',$encryptedString);
		$itsWorthIt = (is_array($encrypted) && !empty($encrypted));

		if($youGottaBigString && $itsWorthIt) { //Let's decrypt it!

			$decrypted = [];
			//foreach char
			foreach($encrypted as $value){
				$value = $this->_flip($value);          //Flip it
				$value = $this->_andReverse($value);    //Reverse it
				$decrypted[] = pack('H*', base_convert($value, 2, 16));
			}

			$decrypted = implode('',$decrypted);

			//Finally decrypt it
			return $this->_actuallyDecrypt($decrypted,$key);
		}else{
			//nope.
			throw new \Exception("Yeah, you ain't ahead of the game.");
		}
	}

	/**
	 * Generate a new encryption key string
	 *
	 * @return string the key
	 */
	public function getNewEncryptionKey()
	{
		//leading 4 based on random dice roll
		$hash = hash('sha256',"4".date(base64_decode(time())).time().microtime());
		//@todo add validation to ensure the key length is correct
		return pack('H*', $hash);
	}

	/**
	 * Flip a binary value, 1111111 => 0000000
	 *
	 * @param string $it    Binary value
	 *
	 * @return string       Flipped binary value
	 */
	private function _flip($it)
	{
		$flipped = '';
		foreach(str_split($it) as $char){
			$flipped .= (string) ($char=='1' ? '0' : '1');

		}
		return $flipped;

	}

	/**
	 * Reverse a binary value, 1110000 => 0000111
	 *
	 * @param string $it    Binary value
	 *
	 * @return string       Reversed binary value
	 */
	private function _andReverse($it)
	{
		return (string) strrev($it);
	}

	/**
	 * @param $plaintext
	 * @param $key
	 *
	 * @return string
	 */
	private function _actuallyEncrypt($plaintext,$key)
	{
		# create a random IV to use with CBC encoding
		$iv_size = mcrypt_get_iv_size($this->cypher, $this->mode);
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);

		# creates a cipher text compatible with AES (Rijndael block size = 128)
		# to keep the text confidential
		# only suitable for encoded input that never ends with value 00h
		# (because of default zero padding)
		$ciphertext = mcrypt_encrypt($this->cypher, $key, $plaintext, $this->mode, $iv);

		# prepend the IV for it to be available for decryption
		# encode the resulting cipher text so it can be represented by a string
		return base64_encode($iv . $ciphertext);
	}

	/**
	 * @param $ciphertext_base64
	 * @param $key
	 *
	 * @return string
	 */
	private function _actuallyDecrypt($ciphertext_base64,$key)
	{
		$ciphertext_dec = base64_decode($ciphertext_base64);
		$iv_size = mcrypt_get_iv_size($this->cypher, $this->mode);

		# retrieves the IV, iv_size should be created using mcrypt_get_iv_size()
		$iv_dec = substr($ciphertext_dec, 0, $iv_size);

		# retrieves the cipher text (everything except the $iv_size in the front)
		$ciphertext_dec = substr($ciphertext_dec, $iv_size);

		# may remove 00h valued characters from end of plain text
		$plaintext_dec = mcrypt_decrypt($this->cypher, $key, $ciphertext_dec, $this->mode, $iv_dec);

		return $plaintext_dec;
	}


}