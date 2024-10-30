from flask import Flask, render_template, request, jsonify
import os
import numpy as np
import tensorflow as tf
import pefile
import cv2
import matplotlib.pyplot as plt

app = Flask(__name__)
model = tf.keras.models.load_model('train_model/modelo3.keras')  # Reemplaza con la ruta a tu modelo

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/select_file', methods=['POST'])
def select_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
    
    # Procesar el archivo
    file_path = os.path.join('uploads', file.filename)
    file.save(file_path)

    try:
        binary_image = convert_to_binary_image(file_path)
        predicted_class, probability = predict_malware(binary_image)

        # Convertir la imagen a PNG y guardarla
        image_path = 'static/binary_image.png'
        plt.imsave(image_path, binary_image.squeeze(), cmap='gray', format='png')

        # Mostrar la predicción
        class_name = show_prediction(predicted_class, probability)

        return jsonify({
            'prediction': class_name,
            'probability': float(probability),
            'image_path': image_path
        })
    except Exception as e:
        return jsonify({'error': str(e)})

def convert_to_binary_image(file_path):
    pe = pefile.PE(file_path)
    sections = ['.data', '.rsrc', '.rdata', '.text']
    binary_image = np.zeros((256, 256), dtype=np.uint8)

    for section in pe.sections:
        section_name = section.Name.decode().strip('\x00')
        if section_name in sections:
            data = section.get_data()
            section_image = np.frombuffer(data, dtype=np.uint8).reshape(-1, 256)[:256, :]

            if section_image.shape[0] < 256:
                pad_size = 256 - section_image.shape[0]
                section_image = np.pad(section_image, ((0, pad_size), (0, 0)), mode='constant', constant_values=0)

            binary_image = np.maximum(binary_image, section_image)

    rgb_image = np.repeat(np.expand_dims(binary_image, axis=-1), 3, axis=-1)
    return rgb_image

def predict_malware(binary_image):
    predictions = model.predict(np.expand_dims(binary_image, axis=0))
    predicted_class = np.argmax(predictions)
    probability = predictions[0][predicted_class]
    return predicted_class, probability

def show_prediction(class_index, probability):
    classes = [
        'Adialer.C', 'Agent.FYI', 'Allaple.A', 'Allaple.L', 'Alueron.gen!J', 
        'Autorun.K', 'C2LOP.gen!g', 'C2LOP.P', 'Dialplatform.B', 'Dontovo.A', 
        'Fakerean', 'Instantaccess', 'Lolyda.AA1', 'Lolyda.AA2', 'Lolyda.AA3', 
        'Lolyda.AT', 'Malex.gen!J', 'No Malware', 'Obfuscator.AD', 'Rbot!gen', 
        'Skintrim.N', 'Swizzor.gen!E', 'Swizzor.gen!I', 'VB.AT', 'Wintrim.BX', 
        'Yuner.A'
    ]
    
    class_name = classes[class_index]
    print(f'Predicted Class: {class_name}, Probability: {probability}')
    return class_name

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    app.run(debug=True)
