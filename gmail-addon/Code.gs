/**
 * Gmail add-on: scans the open email with the Phishing Detector API.
 *
 * Flow: user opens an email -> Gmail calls onGmailMessageOpen -> a "Scan this
 * email" button -> scanCurrentMessage reads the raw message (headers + body + attachments, exactly like a .eml file) ->
 * POST it to /api/scan on our load balancer -> show the verdict as a card.
 *
 * The API address is NOT hard-coded: set the Script Property API_URL
 * (Project Settings > Script properties), e.g. http://<alb-dns-name>
 * It changes on every fresh deploy, and keeps infrastructure details out of git.
 *
 * Scopes (appsscript.json) are the minimum needed:
 *   gmail.addons.current.message.readonly - read ONLY the email the user opened
 *   script.external_request               - call our API
 */

const MAX_BYTES = 1000000;   // the API rejects bigger emails (MAX_EMAIL_BYTES)
const VERDICT_ICON = { Safe: '🟢', Suspicious: '🟠', Phishing: '🔴' };

function onHomepage() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Phishing Detector'))
    .addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText('Open an email to scan it for phishing indicators.')))
    .build();
}

// Opening an email does NOT send it anywhere - the user decides with the button.
// (Privacy: emails can be personal; scanning every opened email would also cost.)
function onGmailMessageOpen(e) {
  const scan = CardService.newAction().setFunctionName('scanCurrentMessage');
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Phishing Detector'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText('Check this email for phishing: sender, links, wording and attachments.'))
      .addWidget(CardService.newTextButton()
        .setText('Scan this email')
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(scan)))
    .build();
}

// Button handler: scan, then replace the card with the result.
function scanCurrentMessage(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(scanMessage(e)))
    .build();
}

function scanMessage(e) {
  // The access token limits us to the message the user is looking at.
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const message = GmailApp.getMessageById(e.gmail.messageId);
  const raw = message.getRawContent();

  if (raw.length > MAX_BYTES) {
    return errorCard('This email is too large to scan (over 1 MB, usually because of attachments).');
  }

  const apiUrl = PropertiesService.getScriptProperties().getProperty('API_URL');
  if (!apiUrl) {
    return errorCard('API_URL is not set. Add it under Project Settings > Script properties.');
  }

  let response;
  try {
    response = UrlFetchApp.fetch(apiUrl.replace(/\/+$/, '') + '/api/scan', {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify({ content: raw }),
      muteHttpExceptions: true,   // handle HTTP errors ourselves instead of throwing
    });
  } catch (err) {
    return errorCard('Could not reach the scanner: ' + err.message);
  }

  const code = response.getResponseCode();
  if (code !== 200) {
    return errorCard('The scanner returned HTTP ' + code + '. Try again in a moment.');
  }

  const headers = response.getHeaders();
  const servedBy = headers['X-Served-By'] || headers['x-served-by'] || '';
  return resultCard(JSON.parse(response.getContentText()), servedBy);
}

function resultCard(result, servedBy) {
  const icon = VERDICT_ICON[result.verdict] || '';
  const card = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader()
      .setTitle(icon + ' ' + result.verdict)
      .setSubtitle('Risk score ' + result.score + '/100'));

  const findings = result.findings || [];
  const section = CardService.newCardSection()
    .setHeader(findings.length ? findings.length + ' indicator(s) found' : 'No phishing indicators found');

  findings.forEach(function (f) {
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel('+' + f.points + ' · ' + f.category)
      .setText(esc(f.title))
      .setBottomLabel(esc(f.detail))
      .setWrapText(true));
  });
  card.addSection(section);

  if (servedBy) {
    card.addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText('<font color="#80868b">Scanned by ' + esc(servedBy) + '</font>')));
  }
  return card.build();
}

// Card text understands a little HTML, and finding details contain text taken from
// the email (URLs, names). Escape it so an attacker can't inject markup into the card.
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function errorCard(text) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Phishing Detector'))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(text)))
    .build();
}
