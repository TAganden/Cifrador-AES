<?php
    
    require_once("php/bloque_cifrador.php");
    require_once("php/cifrador.php");
    
    
    $timer = microtime(true);// para tomar el tiempo de ejecución del cifrado

    $clave = empty($_POST['clave']) ? '' : $_POST['clave'];
    $mensaje = empty($_POST['mensaje']) ? '' : $_POST['mensaje'];
    $cifrado = empty($_POST['cifrado']) ? '' : $_POST['cifrado'];
    $descifrado  = empty($_POST['descifrado'])  ? '' : $_POST['descifrado'];

    $cifrado_resultado = empty($_POST['cifrado_resultado']) ? $cifrado : Cifrador::cifrar_mensaje($mensaje, $clave, 256);
    $descifrado_resultado = empty($_POST['descifrado_resultado']) ? $descifrado  : Cifrador::descifrar_mensaje($cifrado, $clave, 256);
?>

<!doctype html>
<html lang="en">
  <head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
    <link rel="stylesheet" type="text/css" href="css/styles.css">

    <title>Ovejas Electricas</title>
  </head>
  <body>
    <nav class="navbar navbar_estilo">
        <span class="navbar-brand mb-0 h1">MSEG-02: Cifrador AES</span>
    </nav>
    <div class="container">
        <form method="post">
               
            <div class="form-group row">
                <label class="etiqueta" for="input_clave">Clave: </label>
                <input class="form-control" type="text" id="input_clave" name="clave" size="40" value="<?= $clave ?>">
                <small class="form-text text-muted mensaje_ayuda">Ingrese la clave de 32 símbolos para cifrar su mensaje</small>
            </div>
                
            <div class="form-group row">
                <label class="etiqueta" for="input_mensaje">Mensaje: </label>   
                <textarea class="form-control" id="input_mensaje" name="mensaje"><?= htmlspecialchars($mensaje) ?></textarea>
                <small class="form-text text-muted mensaje_ayuda">Ingrese el mensaje que desea cifrar con AES</small>
            </div>
            
            <div class="alert alert-warning" role="alert">
                <span>Tiempo de cifrado: <?= round(microtime(true) - $timer, 3)?> segundos </span>
            </div>
            
            <div class="row"> 
                <div class="form-group col-12 col-sm-12 col-md-6 col-lg-6">
                    <button type="submit" class="btn btn-success" name="cifrado_resultado" value="Encrypt it">Cifrar AES</button>
                    <small class="form-text text-muted mensaje_ayuda">Texto cifrado: </small>
                    <textarea rows="10" class="form-control" name="cifrado"><?= htmlspecialchars($cifrado_resultado) ?></textarea>
                </div>
                <div class="form-group col-12 col-sm-12 col-md-6 col-lg-6">
                    <button type="submit" class="btn btn-warning" name="descifrado_resultado" value="Decrypt it">Descifrar AES</button>
                    <small class="form-text text-muted mensaje_ayuda">Texto descifrado: </small>
                    <textarea rows="10" class="form-control" name="descifrado"><?= htmlspecialchars($descifrado_resultado) ?></textarea>
               </div>
            
            </div>
        </form>
        
    </div>
    
    <footer class="footer">
    
        <div class="footer-copyright py-3 text-center">

            <span><b>Leonardo Ramírez Salazar</b></span>
        </div>
    
    </footer>

    
    
    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>
  
  
   </body>
</html>



 
