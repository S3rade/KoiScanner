
function email_scanner(){
    var clientId = '653929975108-bfco46qcf5dgp31ghfagp94sq9b65qv5.apps.googleusercontent.com';
    var apiKey= 'AIzaSyAp8wM30sy66PG55ziGQEyogUClS9T9O_E';
    var scopes = 'https://www.googleapis.com/auth/gmail.readonly'; 

    gapi.client.setApiKey(apiKey);
    window.setTimeout(checkAuth, 1);
}

function checkAuth() {
    gapi.auth.authorize({
      client_id: clientId,
      scope: scopes,
      immediate: true
    }, handleAuthResult);
  }

function handleAuthClick() {
    gapi.auth.authorize({
      client_id: clientId,
      scope: scopes,
      immediate: false
    }, handleAuthResult);
    return false;
  }

function handleAuthResult(authResult) {
    if(authResult && !authResult.error) {
      loadGmailApi();
      $('#authorize-button').remove();
      $('.table-inbox').removeClass("hidden");
    } else {
      $('#authorize-button').removeClass("hidden");
      $('#authorize-button').on('click', function(){
        handleAuthClick();
      });
    }
  }
  
function loadGmailApi() {
    gapi.client.load('gmail', 'v1', displayInbox);
  }
  function displayInbox() {
    var request = gapi.client.gmail.users.messages.list({
      'userId': 'tpmpuser123@gmail.com',
      'labelIds': 'Inbox',
      'maxResults': 10
    });
  
    request.execute(function(response) {
      $.each(response.messages, function() {
        var messageRequest = gapi.client.gmail.users.messages.get({
          'userId': 'tpmpuser123@gmail.com',
          'id': this.id
        });
  
        messageRequest.execute(appendMessageRow);
      });
    });
  }

  function appendMessageRow(message) {
    $('.table-inbox tbody').append(
      '<tr>\
        <td>'+getHeader(message.payload.headers, 'From')+'</td>\
        <td>'+getHeader(message.payload.headers, 'Subject')+'</td>\
        <td>'+getHeader(message.payload.headers, 'Date')+'</td>\
      </tr>'
    );
  }

  function appendMessageRow(message) {
    $('.table-inbox tbody').append(
      '<tr>\
        <td>'+getHeader(message.payload.headers, 'From')+'</td>\
        <td>\
          <a href="#message-modal-' + message.id +
            '" data-toggle="modal" id="message-link-' + message.id+'">' +
            getHeader(message.payload.headers, 'Subject') +
          '</a>\
        </td>\
        <td>'+getHeader(message.payload.headers, 'Date')+'</td>\
      </tr>'
    );
  }

document.addEventListener('DOMContentLoaded', function(){
    var checkPageButton = document.getElementById('Scan_Email');
    
    checkPageButton.addEventListener('click', email_scanner);

});

