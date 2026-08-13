function Decrypt-ChromiumPassword {
    param(
        [string]$EncryptedBase64,
        [string]$KeyBase64
    )
    
    Add-Type -AssemblyName System.Security
    
    $encrypted = [Convert]::FromBase64String($EncryptedBase64)
    $key = [Convert]::FromBase64String($KeyBase64)
    
    # Remove v10/v11 prefix
    $encrypted = $encrypted[3..($encrypted.Length-1)]
    
    $nonce = $encrypted[0..11]
    $ciphertext = $encrypted[12..($encrypted.Length-1)]
    
    $aes = [System.Security.Cryptography.AesGcm]::new($key)
    $plaintext = New-Object byte[] ($ciphertext.Length - 16)
    
    $aes.Decrypt($nonce, $ciphertext[0..($ciphertext.Length-17)], $ciphertext[($ciphertext.Length-16)..($ciphertext.Length-1)], $plaintext)
    
    return [System.Text.Encoding]::UTF8.GetString($plaintext)
}
