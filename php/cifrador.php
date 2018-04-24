<?php
/***************************************************************************************************************************
 * 
 * Implementación de un cifrador y descifrador de mensajes mediante el algoritmo AES
 *
 * Leonardo Ramírez Salazar
 * 
 ***************************************************************************************************************************/

Class Cifrador extends Bloque_cifrador //heredamos de la clase Bloque_cifrador
{

    /*
     * Cifra un mensaje utilizado el algoritmo AES
     * La función recibe un mensaje de texto, una clave para descifrar el mensaje 
     * y el tamaño en bits de la clave que vamos a aplicar
     */
    public static function cifrar_mensaje($mensaje, $clave, $nBits)
    {
        $blockSize = 16; // tamaño del bloque a 16 bytes 
        //chequeamos tamaño de la clave acorde a los valores permitidos
        if (!($nBits == 128 || $nBits == 192 || $nBits == 256)) return ''; 

        $nBytes = $nBits / 8; // cantidad de bytes
        $clave_bytes = array();
        
        for ($i = 0; $i < $nBytes; $i++){ 
            $clave_bytes[$i] = ord(substr($clave, $i, 1)) & 0xff;//obtenemos la clave en bytes 
        }
        $llave = Bloque_cifrador::cifrar_bloque($clave_bytes, Bloque_cifrador::keyExpansion($clave_bytes));
        $llave = array_merge($llave, array_slice($llave, 0, $nBytes - 16)); 

        // inicializamos los primerso 8bytes de nuestro contador de bloques once 
        $counterBlock = array();
        
        $val = floor(microtime(true) * 1000); // timestamp: en milisegundos
        $valMs = $val % 1000;
        $valSec = floor($val / 1000);
        $valRnd = floor(rand(0, 0xffff));

        for ($i = 0; $i < 2; $i++) $counterBlock[$i] = self::corrimiento_derecha($valMs, $i * 8) & 0xff;
        for ($i = 0; $i < 2; $i++) $counterBlock[$i + 2] = self::corrimiento_derecha($valRnd, $i * 8) & 0xff;
        for ($i = 0; $i < 4; $i++) $counterBlock[$i + 4] = self::corrimiento_derecha($valSec, $i * 8) & 0xff;

        // y lo convertimos a un string para ser procesado en las rondas de cifrado
        $ctrTxt = '';
        for ($i = 0; $i < 8; $i++) $ctrTxt .= chr($counterBlock[$i]);

        // generamos el conjunto de llaves expandidas que utilizaremos en el cifrado
        $expand_llave = Bloque_cifrador::keyExpansion($llave);
        

        $blockCount = ceil(strlen($mensaje) / $blockSize); //cantidad de bloques en el mensaje
        $texto_cifrado = array(); // almacenaremos aquí el texto cifrado

        //ciframos cada bloque del mensaje en AES
        for ($b = 0; $b < $blockCount; $b++) {
           
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c] = self::corrimiento_derecha($b, $c * 8) & 0xff;
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c - 4] = self::corrimiento_derecha($b / 0x100000000, $c * 8);
            
            $cifrado_temp = Bloque_cifrador::cifrar_bloque($counterBlock, $expand_llave); // ciframos el bloque

            //para el bloque final tenemos que ajustar el tamaño pues no necesariamente será un bloque completo
            $blockLength = $b < $blockCount - 1 ? $blockSize : (strlen($mensaje) - 1) % $blockSize + 1;
            $cifradoByte = array();

            for ($i = 0; $i < $blockLength; $i++) { 
                $cifradoByte[$i] = $cifrado_temp[$i] ^ ord(substr($mensaje, $b * $blockSize + $i, 1));
                $cifradoByte[$i] = chr($cifradoByte[$i]);
            }
            $texto_cifrado[$b] = implode('', $cifradoByte); 
        }

        
        $texto_cifrado = $ctrTxt . implode('', $texto_cifrado);
        $texto_cifrado = base64_encode($texto_cifrado); //pasamos a texto codificando nuestro hexadecimal a ASCII
        return $texto_cifrado;
    }


    /*
     * Descifra un mensaje utilizado el algoritmo AES
     * La función recibe un mensaje de texto cifrado, la clave para descifrar el mensaje 
     * y el tamaño en bits de la clave que vamos a aplicar
     */
    public static function descifrar_mensaje($texto_cifrado, $clave, $nBits)
    {
        $blockSize = 16; // tamaño del bloque
        if (!($nBits == 128 || $nBits == 192 || $nBits == 256)) return ''; //claves permitidas para 128/192/256 bits
        $texto_cifrado = base64_decode($texto_cifrado); //decodificamos a hexadecimal

        // usamos AES para cifrar la clave 
        $nBytes = $nBits / 8; // cantidad de bytes
        $clave_bytes = array();
        
        for ($i = 0; $i < $nBytes; $i++){
            $clave_bytes[$i] = ord(substr($clave, $i, 1)) & 0xff;
        }
        $llave = Bloque_cifrador::cifrar_bloque($clave_bytes, Bloque_cifrador::keyExpansion($clave_bytes));
        $llave = array_merge($llave, array_slice($llave, 0, $nBytes - 16)); // expand key to 16/24/32 bytes long

        $counterBlock = array();
        $ctrTxt = substr($texto_cifrado, 0, 8);
        for ($i = 0; $i < 8; $i++){
            $counterBlock[$i] = ord(substr($ctrTxt, $i, 1));
        }
        
        // generamos el conjunto de llaves de descifrado
        $expand_llave = Bloque_cifrador::keyExpansion($llave);

        // separamos el texto cifrado en bloques (importante saltarse lo primeros 8 bytes)
        $nBlocks = ceil((strlen($texto_cifrado) - 8) / $blockSize);
        $temp = array();
        for ($b = 0; $b < $nBlocks; $b++){
            $temp[$b] = substr($texto_cifrado, 8 + $b * $blockSize, 16);
        }
        $texto_cifrado = $temp; // el texto cifrado es ahora un arreglo de bloques de cadenas 

        // almacenaremos aquí el mensaje descifrado
        $mensaje = array();

        for ($b = 0; $b < $nBlocks; $b++) {
            
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c] = self::corrimiento_derecha($b, $c * 8) & 0xff;
            for ($c = 0; $c < 4; $c++) $counterBlock[15 - $c - 4] = self::corrimiento_derecha(($b + 1) / 0x100000000 - 1, $c * 8) & 0xff;

            $cifrado_temp = Bloque_cifrador::cifrar_bloque($counterBlock, $expand_llave); // encrypt counter block

            $mensajeByte = array();
            for ($i = 0; $i < strlen($texto_cifrado[$b]); $i++) {
                //xor 
                $mensajeByte[$i] = $cifrado_temp[$i] ^ ord(substr($texto_cifrado[$b], $i, 1));
                $mensajeByte[$i] = chr($mensajeByte[$i]);

            }
            $mensaje[$b] = implode('', $mensajeByte);
        }

        // convertimoe el arreglo en una cadena antes de devolver el mensaje descifrado
        $mensaje = implode('', $mensaje);

        return $mensaje;
    }
    
    
    private static function corrimiento_derecha($a, $b)
    {
        $a &= 0xffffffff;
        $b &= 0x1f; 
        if ($a & 0x80000000 && $b > 0) { 
            $a = ($a >> 1) & 0x7fffffff; 
            $a = $a >> ($b - 1); 
        } else { 
            $a = ($a >> $b); 
        }
        return $a;
    }

}// fin de clase

// EOF
