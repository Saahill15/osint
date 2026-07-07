// Google Apps Script for receiving POST requests from the backend and appending rows to a Google Sheet.
// 1. Open Google Sheets.
// 2. Extensions -> Apps Script.
// 3. Paste this code and save.
// 4. Deploy -> New deployment -> Web app.
// 5. Execute as: Me
// 6. Who has access: Anyone
// 7. Copy the web app URL and set it as GOOGLE_SHEETS_WEBHOOK_URL in your backend environment.

function doPost(e) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
  const payload = e.postData?.contents ? JSON.parse(e.postData.contents) : {};

  const row = [
    payload.timestamp || new Date().toISOString(),
    payload.phase || '',
    payload.query || '',
    payload.status || '',
    payload.responseStatus || '',
    payload.source || '',
    typeof payload.result === 'string' ? payload.result : JSON.stringify(payload.result || ''),
  ];

  sheet.appendRow(row);

  return ContentService.createTextOutput(JSON.stringify({ ok: true })).setMimeType(ContentService.MimeType.JSON);
}
