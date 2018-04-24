<?php

/***************************************************************************************************************************
 * 
 * Implementación de un cifrador de bloques AES
 * Clase que toma un bloque codificado en bytes y un conjunto expandido de claves en bytes y a partir de ello, cifra o
 * decifra el bloque aplicando un algoritmo AES
 * 
 * Leonardo Ramírez Salazar
 * 
 ***************************************************************************************************************************/


Class Bloque_cifrador{
    
    //Campos de Clase
    //----------------------------------------------------------------------------------------------------------------------
    
    /*
    * La s-Box nos permite calcular los inversos multiplicativos en el campo de Galois de 256 elementos = GF(2^8) 
    * La s-Box la utilizaremos para las operaciones de las capas de sustitución de bytes y para la expansión de claves 
    */
    private static $_sBox = array(
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    );

    // La constante de ronda es utilizada para la expansión de llaves ( la primer columna es 2^(r-1) in GF(2^8) ).
    private static $_const_Ronda = array(
        array(0x00, 0x00, 0x00, 0x00),
        array(0x01, 0x00, 0x00, 0x00),
        array(0x02, 0x00, 0x00, 0x00),
        array(0x04, 0x00, 0x00, 0x00),
        array(0x08, 0x00, 0x00, 0x00),
        array(0x10, 0x00, 0x00, 0x00),
        array(0x20, 0x00, 0x00, 0x00),
        array(0x40, 0x00, 0x00, 0x00),
        array(0x80, 0x00, 0x00, 0x00),
        array(0x1b, 0x00, 0x00, 0x00),
        array(0x36, 0x00, 0x00, 0x00)
    );
    
    //----------------------------------------------------------------------------------------------------------------------
    
    
    /* CAPAS DE DIFUSIÓN */
    //----------------------------------------------------------------------------------------------------------------------
    
    /**
     * Intercambio de columnas
     * En este paso se realiza una transposición donde cada fila del "estado" es rotada de
     * manera cíclica un número determinado de veces
     */
    private static function shiftRows($estado, $block_size){
        
        $temporal = array(4);
        for ($fila = 1; $fila < 4; $fila++) {
            for ($columna = 0; $columna < 4; $columna++) {
                $temporal[$columna] = $estado[$fila][($columna + $fila) % $block_size]; //copiamos a temporal
                
            } 
            for ($columna = 0; $columna < 4; $columna++) {
                $estado[$fila][$columna] = $temporal[$columna]; //intercambiamos columnas 
            } 
        } 
        return $estado; 
    }

    /*
     * Mezclado de columnas 
     * En nuestras columnas de estado, combinamos los cuatro bytes en cada columna usando una transformación lineal.    
     */
    private static function mixColumns($estado){
        
        for ($columna = 0; $columna < 4; $columna++){
            $a = array(4); 
            $b = array(4); 
            
            for ($i = 0; $i < 4; $i++){
                $a[$i] = $estado[$i][$columna];
                $b[$i] = $estado[$i][$columna] & 0x80 ? $estado[$i][$columna] << 1 ^ 0x011b : $estado[$i][$columna] << 1;
            }
            
            $estado[0][$columna] = $b[0] ^ $a[1] ^ $b[1] ^ $a[2] ^ $a[3]; // 2*a0 + 3*a1 + a2 + a3
            $estado[1][$columna] = $a[0] ^ $b[1] ^ $a[2] ^ $b[2] ^ $a[3]; // a0 * 2*a1 + 3*a2 + a3
            $estado[2][$columna] = $a[0] ^ $a[1] ^ $b[2] ^ $a[3] ^ $b[3]; // a0 + a1 + 2*a2 + 3*a3
            $estado[3][$columna] = $a[0] ^ $b[0] ^ $a[1] ^ $a[2] ^ $b[3]; // 3*a0 + a1 + a2 + 2*a3
        }
        return $estado;
    }
    //----------------------------------------------------------------------------------------------------------------------
    

    /* CAPAS DE CONFUSIÓN */
    //----------------------------------------------------------------------------------------------------------------------
    
    /**
     * Capa de adición de clave
     * Se hace un XOR entre la subclave de ronda, derivada de la clave principal en el
     * programa de clave. 
     */
    private static function addRoundKey($estado, $claves, $ronda, $block_size){
        
        for ($fila = 0; $fila < 4; $fila++) {
            for ($columna = 0; $columna < $block_size; $columna++){ 
                $estado[$fila][$columna] ^= $claves[$ronda * 4 + $columna][$fila];
            }
        }
        return $estado;
    }

    /**
     * Capa de sustitución de bytes
     * Realizamos una sustitución no lineal donde cada byte es reemplazado con otro utilizando
     * la s-box con valores matemáticamente definidos.
     */
    private static function subBytes($estado, $block_size){
        
        for ($fila = 0; $fila < 4; $fila++) {
            for ($columna = 0; $columna < $block_size; $columna++){
                $estado[$fila][$columna] = self::$_sBox[$estado[$fila][$columna]];
            }
        }
        return $estado;
    }
    //----------------------------------------------------------------------------------------------------------------------
    
    
    /* EXPANSION DE CLAVES  */
    //----------------------------------------------------------------------------------------------------------------------
    //Las siguientes son operaciones clave para la generar la suficiente cantidad de claves que encesitamos 
    //para encriptar nuestro bloque
    
    /**
    * Sustitución de clave
    * Pasamos cada palabra de 4 bytes (cada clave) por nuestra s-Box para transformarla en algo distinto
    */
    private static function sustituirClave($clave)
    {
        for ($i = 0; $i < 4; $i++) $clave[$i] = self::$_sBox[$clave[$i]];
        return $clave;
    }

    /**
     * Rotación de clave
     * Rotamos la clave una posición de tal manera que el byte que esta en el "top" de la columna 
     * se desplace del todo abajo. 
     */
    private static function rotarClave($clave){
        
        $temp = $clave[0];
        for ($i = 0; $i < 3; $i++){ $clave[$i] = $clave[$i + 1];}
        $clave[3] = $temp;
        return $clave;
    }

    /*
     * Generamos las matrices de llaves que utilizaremos para el cifrado del bloque  
     */
    public static function keyExpansion($llave){
        
        $block_size = 4; // tamaño del bloque en bytes
        $llave_size = count($llave) / 4; // longitud de la clave en bytes (4 para claves de 128 bits)
        $numero_rondas = $llave_size + 6; // número de rondas (10 para claves de 128 bits);

        $llaves_salida = array();
        $temp = array();

        for ($i = 0; $i < $llave_size; $i++) {
            $r = array($llave[4 * $i], $llave[4 * $i + 1], $llave[4 * $i + 2], $llave[4 * $i + 3]);
            $llaves_salida[$i] = $r;
        }

        for ($i = $llave_size; $i < ($block_size * ($numero_rondas + 1)); $i++) {
            
            $llaves_salida[$i] = array();
            
            for ($t = 0; $t < 4; $t++){ 
                $temp[$t] = $llaves_salida[$i - 1][$t];
            }
            //paso cada byte por una s-box, si se trata de la última clave de la ronda 
            //anterior efectúo la rotación de bytes
            if ($i % $llave_size == 0) {
                
                $temp = self::sustituirClave(self::rotarClave($temp)); 
                for ($t = 0; $t < 4; $t++){ 
                    //efectúo un xor de la columna con la constante de ronda que es diferente
                    //para cada ronda
                    $temp[$t] ^= self::$_const_Ronda[$i / $llave_size][$t];
                }
            } 
            else{ 
                if ($llave_size > 6 && $i % $llave_size == 4) {
                    $temp = self::sustituirClave($temp);
                }
            }
            for ($t = 0; $t < 4; $t++){ 
                $llaves_salida[$i][$t] = $llaves_salida[$i - $llave_size][$t] ^ $temp[$t];
            }
        }
        return $llaves_salida;
    }
    //----------------------------------------------------------------------------------------------------------------------

    /*
     * Función para el cifrado de un bloque mediante AES
     * Este procedimiento aplica tanto para el cifrado como para el descifrado pues la variación se da en la
     * inversión de las capas de difusión y confusión
    */
    public static function cifrar_bloque($mensaje, $claves){
        
        $block_size = 4; // tamaño del bloque en bytes
        $numero_rondas = count($claves) / $block_size - 1; // número de rondas (10 para claves de 128 bits);

        $estado = array(); // inicializamos nuestro bloque de 4xTamaño de bloque
        for ($i = 0; $i < 4 * $block_size; $i++){ 
            $estado[$i % 4][floor($i / 4)] = $mensaje[$i];
        }
            
        //arrancamos con una adición de clave para introducir el estado de cifrado en el ciclo de rondas
        $estado = self::addRoundKey($estado, $claves, 0, $block_size); 
        
        // aplicamos la cantidad de rondas para el bloque
        for ($ronda = 1; $ronda < $numero_rondas; $ronda++) { 
            $estado = self::subBytes($estado, $block_size);
            $estado = self::shiftRows($estado, $block_size);
            $estado = self::mixColumns($estado, $block_size);
            $estado = self::addRoundKey($estado, $claves, $ronda, $block_size);
        }
        
        //En la ronda final, nos saltamos el mezclado de columnas, no es necesario
        $estado = self::subBytes($estado, $block_size);
        $estado = self::shiftRows($estado, $block_size);
        $estado = self::addRoundKey($estado, $claves, $numero_rondas, $block_size);

        $bloque_cifrado = array(4 * $block_size); 
        
        for ($i = 0; $i < 4 * $block_size; $i++){ 
            $bloque_cifrado[$i] = $estado[$i % 4][floor($i / 4)];
        }
        return $bloque_cifrado;
    }

} // fin de clase

// EOF




