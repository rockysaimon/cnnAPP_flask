document.getElementById('file-input').addEventListener('change', function() {
    const fileName = this.files[0] ? this.files[0].name : "No se eligió ningún archivo";
    document.getElementById('file-name').textContent = fileName;
});

function selectFile() {
    const fileInput = document.getElementById('file-input');
    fileInput.click();

    fileInput.onchange = async function() {
        if (fileInput.files.length > 0) {
            const fileName = fileInput.files[0].name;
            document.getElementById('file-name').textContent = fileName;

            // Crear un FormData con el archivo seleccionado
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            // Realizar la predicción
            try {
                const response = await fetch('/select_file', {
                    method: 'POST',
                    body: formData
                });

                if (response.ok) {
                    const result = await response.json();
                    document.getElementById('prediction').textContent = `Predicción: ${result.prediction} (Probabilidad: ${result.probability}%)`;
                    const image = document.getElementById('image_path');
                    const timestamp = new Date().getTime();
                    image.src = `${result.image_path}?t=${timestamp}`;
                    image.style.visibility = 'visible';
                } else {
                    document.getElementById('prediction').textContent = "Error al realizar la predicción";
                }
            } catch (error) {
                console.error("Error en la solicitud de predicción:", error);
            }
        }
    };
}
