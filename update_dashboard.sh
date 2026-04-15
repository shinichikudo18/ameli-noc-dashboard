# Update Dashboard Script
# Run this on VMOS via: curl -skL https://raw.githubusercontent.com/shinichikudo18/ameli-noc-dashboard/master/update_dashboard.sh | bash

REPO="shinichikudo18/ameli-noc-dashboard"
BRANCH="master"
DEST="/tmp/ameli.html"

echo "Descargando dashboard desde GitHub..."
curl -skL "https://raw.githubusercontent.com/${REPO}/${BRANCH}/ameli.html" -o "$DEST"

if [ $? -eq 0 ]; then
    echo "OK: Dashboard actualizado en $DEST"
    ls -la "$DEST"
else
    echo "ERROR: Fallo la descarga"
    exit 1
fi
