var developerKey = gcbrowserkey;
var clientId = gcid;
var appId = gcappid;
var folder_id = gcfolderid;

var scope = ['https://www.googleapis.com/auth/drive.file'];

var pickerApiLoaded = false;
var oauthToken;

function loadPicker() {
  gapi.load('auth', {'callback': onAuthApiLoad});
  gapi.load('picker', {'callback': onPickerApiLoad});
}

function onAuthApiLoad() {
  window.gapi.auth.authorize(
      {
        'client_id': clientId,
        'scope': scope,
        'immediate': false
      },
      handleAuthResult);
}

function onPickerApiLoad() {
  pickerApiLoaded = true;
  createPicker();
}

function handleAuthResult(authResult) {
  if (authResult && !authResult.error) {
    oauthToken = authResult.access_token;
    createPicker();
  }
}

function createPicker() {
  if (pickerApiLoaded && oauthToken) {
    var view = new google.picker.View(google.picker.ViewId.DOCS);
    view.setParent(folder_id);
    var picker = new google.picker.PickerBuilder()
        .enableFeature(google.picker.Feature.NAV_HIDDEN)
        .enableFeature(google.picker.Feature.MULTISELECT_ENABLED)
        .addView(view)
        .setAppId(appId)
        .setOAuthToken(oauthToken)
        .setDeveloperKey(developerKey)
        .setCallback(pickerCallback)
        .build();
      picker.setVisible(true);
  }
}

function pickerCallback(data) {
  if (data.action == google.picker.Action.PICKED) {
    location.reload();
  }
}
