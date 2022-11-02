HOME_PATH=/home/centos
CURRENT_PATH=$HOME_PATH/worsica_web
if [[ -z $(echo $(cat $CURRENT_PATH/WORSICA_VERSION)) ]]; then
	echo 'ERROR: No WORSICA_VERSION file set. Create this file and set version number (0.9.0)'
	exit 1
fi
WORSICA_VERSION=$(cat $CURRENT_PATH/WORSICA_VERSION)
echo "Actual version: ${WORSICA_VERSION}"

WORSICA_NEXT_VERSION=$(echo ${WORSICA_VERSION} | awk -F. -v OFS=. '{$NF++;print}')
echo "Next version: ${WORSICA_NEXT_VERSION}"
echo $WORSICA_NEXT_VERSION > WORSICA_VERSION
WORSICA_VERSION=$(cat $CURRENT_PATH/WORSICA_VERSION)
echo "Finished! Updated to version: ${WORSICA_VERSION}"
cd ${CURRENT_PATH}
git add $CURRENT_PATH/WORSICA_VERSION && git commit -m "Updated tag to v${WORSICA_VERSION}" && git push
git tag -a v${WORSICA_VERSION} -m "Version v${WORSICA_VERSION}" && git push --tags
cd ..
echo "Done!"