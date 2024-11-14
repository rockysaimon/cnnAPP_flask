document.getElementById('file-input').addEventListener('change', function() {
    const fileName = this.files[0] ? this.files[0].name : "No se eligió ningún archivo";
    document.getElementById('file-name').textContent = fileName;
});
/*
"Escucha" cambios en el campo de selección de archivos (file-input)
cuando el usuario selecciona un archivo y muestra el nombre del archivo .exe en la página.*/

function selectFile() {
    const fileInput = document.getElementById('file-input');
    fileInput.click();
/*es el que permite seleccionar el archivo*/

    fileInput.onchange = async function() {
        if (fileInput.files.length > 0) {
            const fileName = fileInput.files[0].name;
            document.getElementById('file-name').textContent = fileName;

            // Crear un FormData con el archivo seleccionado
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
    /*Cuando se selecciona el archivo, lo guarda en formData para enviarlo al servidor.*/
            // Realizar la predicción
            try {
                const response = await fetch('/select_file', {
                    method: 'POST',
                    body: formData
                });
    /*Realiza una solicitud POST a la ruta /select_file, enviando el archivo seleccionado al servidor Flask o sea, main.py
    para poder convertirlo y procesarlo como imagen*/
                if (response.ok) { /*varifica si la solicitud es exitosa*/
                    const result = await response.json();
                    document.getElementById('prediction').textContent = `Predicción: ${result.prediction} (Probabilidad: ${result.probability}%)`;
                    const image = document.getElementById('image_path');
                    const timestamp = new Date().getTime();
                    image.src = `${result.image_path}?t=${timestamp}`;
                    image.style.visibility = 'visible';
                } else {
                    document.getElementById('prediction').textContent = "Error al realizar la predicción";
                    /*Si la solicitud es exitosa, muestra la predicción, la probabilidad y carga la imagen 
                    de la predicción con un timestamp para evitar problemas de caché (porque al cambiar de archivo,
                    la imagen que se mostraba era siempre del primero, por eso se usó esto)*/
                }
            } catch (error) {
                console.error("Error en la solicitud de predicción:", error);
            }
        }
    };
}
