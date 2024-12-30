while IFS= read -r line
	do
		echo ${line}
		Domain=$line
		heading=$line
		#Domain="wnmxc8532uid.biz.id"
		#heading="wnmxc8532uid.biz.id"

		curl --compressed -s -H "API-Key: 00e3c013-c495-4ccd-8277-93a33d577bd4" "https://urlscan.io/api/v1/search/?q=domain:${Domain}" -o "$Domain"-raw.txt
		ID=$(cat ${Domain}-raw.txt | grep _id | awk -F'"' '{print $4}')

		while IFS= read -r line
			do
				Malicious=$(curl -s -H "API-Key: 00e3c013-c495-4ccd-8277-93a33d577bd4" https://urlscan.io/result/${line} | grep "Malicious")
				if [[ "${Malicious}" ]]; then
					echo "Malicious"
					Malicious=$(curl -s -H "API-Key: 00e3c013-c495-4ccd-8277-93a33d577bd4" https://urlscan.io/result/${line} -o "$Domain"-result.txt)
					URL=$(cat ${Domain}-result.txt | grep "Full URL" | head -1 | awk -F' ' '{print $2}')
					URL=${URL##*://}
					URL=${URL%<*}
					URL=$(echo ${URL} | sed 's|/|_|g;')
					echo ${URL}
					curl -s -H "API-Key: 00e3c013-c495-4ccd-8277-93a33d577bd4" "https://urlscan.io/screenshots/${line}.png" -o "$URL".png
					PNG="$URL".png
					PNG_Path="/Users/putras/Downloads/Datashet_Phishing/$PNG"
					curl --compressed -s -H "API-Key: f1bc3a23-43ee-4ce3-9ce7-51fd6773d685" "https://urlscan.io/dom/${line}" -o "$URL".html
					DOM=$(cat "$URL".html)
					DOM=$DOM

					if [[ "$DOM" == *$'\0'* ]]; then
						echo "The string contains null bytes."
					fi


					
					# Create a Python script to generate a .docx file with an image
cat <<EOF > create_docx_with_image.py
# -*- coding: UTF-8 -*-
import sys
from docx import Document
from docx.shared import Inches
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT

# Create a new Document
doc = Document()

# Add a heading
doc.add_heading('$Domain', level=1)

# Add an image (make sure to provide the correct path to your image)
image_paragraph = doc.add_paragraph()
run = image_paragraph.add_run()
run.add_picture('$PNG_Path', width=Inches(5.0))

# Center the Image
image_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

# Add a page break
doc.add_page_break()

sanitized_content = ''.join(char for char in """$DOM""" if ord(char) >= 32)

# Add a paragraph
doc.add_paragraph(sanitized_content)

# Save the document
doc.save('$URL.docx')
EOF
					# Run the Python Script
					python3 create_docx_with_image.py 

					# Clean Up
					rm create_docx_with_image.py

					echo ${URL} >> Malicious_phishing.txt
				fi
			done <<< "$ID"
	done < datasheet-phishing-domain.txt
		

#curl https://urlscan.io/result/${ID}
#curl https://urlscan.io/screenshots/${ID}.png
#curl https://urlscan.io/screenshots/296311a7-dd38-4134-9f0f-a2e1bd42b40d.png  
#curl https://urlscan.io/dom/296311a7-dd38-4134-9f0f-a2e1bd42b40d.png -o 296311a7-dd38-4134-9f0f-a2e1bd42b40d

#Lakukan curl satu2 jika banyak _id nya.
#Check Potentially Malicious.
#Jika ya, download screenshots dan DOM.