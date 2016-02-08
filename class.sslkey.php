<?php

/**
 * @author: Daryl Blake, email darylblake@gmail.com
 * NOTE: I am a little bit fragile, and if you dont specify all of the $dn arguements i wont work.
 * @todo add handlers for the above.
 * @tutorial This is my first mini project file thing I am sharing with the public.
 * 

USAGE:
include 'class.sslkey.php';

$keyattributes = array(
        'keysize' => 1024,
        'days' => 365,
        'digest' => 'RSA-SHA1'
);
$dn= array(
            "countryName" => "NZ",
            "stateOrProvinceName" => 'auckland',
            "localityName" => 'auckland',
            "organizationName" => 'test123',
            "organizationalUnitName" => 're',
            "commonName" => 'daryl',
            "emailAddress" => 'darylblake@gmail.com'
);

$key = new SSLKey ($keyattributes, $dn);

$key->generateKeys();

echo $key->getPublicKey(); //echo public key.
echo $key->getPrivateKey(); //echo private key.
echo $key->getCertificate(); //echo the cert.

 
 */

class SSLKey {
    //requires OPEN-SSL PHP openssl module enabled and openssl installed on the host. 
    
    private $_keyname;							//Name for the key.
    private $_keysize = 1024;						//Length of Key ( default 1024)
    private $_password = null;						//Key Password (if applicable)
    private $_publickey;						//Public key's content
    private $_privatekey;						//Private key's content
    private $_days = 365;						//Key Duration in days.
    private $_csrcert;							//CSR Cert
    private $_digest;						//Digest encryption method to be used. For More Info see: http://nz.php.net/manual/en/function.openssl-get-md-methods.php
    private $_openSSLConfigFile = '/etc/ssl/openssl.cnf';		//path to openssl config file. (default for ubuntu/debian)
    private $_keydata = array();					//DN data. 
	
    /* 
     * Digest Options: 
     * 
    [2] => DSA-SHA1
    [3] => DSA-SHA1-old
    [4] => DSS1
    [9] => RSA-MD2
    [10] => RSA-MD4
    [11] => RSA-MD5
    [12] => RSA-RIPEMD160
    [13] => RSA-SHA
    [14] => RSA-SHA1
    [15] => RSA-SHA1-2
    [16] => RSA-SHA224
    [17] => RSA-SHA256
    [18] => RSA-SHA384
    [19] => RSA-SHA512
    [28] => dsaWithSHA1
    [29] => dss1
    [32] => md2WithRSAEncryption
    [34] => md4WithRSAEncryption
    [36] => md5WithRSAEncryption
    [37] => ripemd
    [39] => ripemd160WithRSA
    [40] => rmd160
    [43] => sha1WithRSAEncryption
    [45] => sha224WithRSAEncryption
    [47] => sha256WithRSAEncryption
    [49] => sha384WithRSAEncryption
    [51] => sha512WithRSAEncryption
    [52] => shaWithRSAEncryption
    [53] => ssl2-md5
    [54] => ssl3-md5
    [55] => ssl3-sha1
     */
	
	
    public function __construct($options = array(), $dn = array())
    {
        if(isset($options['keysize']) && intval($options['keysize']) >= 32)
        {
            $this->_keysize = intval($options['keysize']);
        }
        if(isset($options['password']))
        {
            $this->_password = $options['password'];
        }
        if(isset($options['keyname']))
        {
            $this->_keyname = $options['keyname'];
        }
        if(isset($options['days']))
        {
            $this->_days = $options['days'];
        }
		if(isset($options['digest']))
		{
			$this->_digest = $options['digest'];
		}
		$this->_keydata = $dn;
    }    
    public function generateKeys() // .key file
    {
        // CONFIG
        $configargs = array(
            'config' => $this->_openSSLConfigFile,
            'digest_alg' => $this->_digest,
            'req_extensions'   => 'v3_req',
            'encrypt_key' => false,
            'x509_extensions' => 'v3_ca',
            'private_key_bits' => $this->_keysize,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        );
        $privkey = openssl_pkey_new($configargs);
        $csr = openssl_csr_new($this->_keydata, $privkey);
        $sscert = openssl_csr_sign($csr, null, $privkey, $this->_days);
        openssl_x509_export($sscert, $this->_publickey);
        openssl_pkey_export($privkey, $this->_privatekey, $this->_password);
        openssl_csr_export($csr, $this->_csrcert);
    }
    public function getPublicKey($filelocation = "")
    {
        if($filelocation)
        {
            return file_put_contents($filelocation, $this->_publickey);
        } 
        else 
        {
            return $this->_publickey;
        }
    }
    public function getPrivateKey($filelocation = "")
    {
        if($filelocation)
        {
            return file_put_contents($filelocation, $this->_privatekey);
        } 
        else 
        {
            return $this->_privatekey;
        }
    }    
    public function getCertificate($filelocation = "")
    {
        if($filelocation)
        {
            return file_put_contents($filelocation, $this->_csrcert);
        } 
        else 
        {
            return $this->_csrcert;
        }
    }    
}


?>
