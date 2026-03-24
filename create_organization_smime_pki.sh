#!/bin/sh

# create_organization_smime_pki.sh

# S/MIME certificate creation

# Person A
./create_smime.sh person_a@gmail.com persona_gmail_2026
./create_smime.sh person_a@icloud.com persona_icloud_2026

# Person B
./create_smime.sh person_b@gmail.com personb_gmail_2026
./create_smime.sh person_b@icloud.com personb_icloud_2026
./create_smime.sh person_b@school.edu personb_school_2026
