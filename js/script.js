$.getJSON('/index.json', function(data) {
  // get latest generated JSON
  var latest = data[data.length-1];
  $('#update').html(latest);

  $.getJSON("/"+latest+".json", function(data) {
    var sites = Object.keys(data);
    var data_set = new Array();
    sites.sort();
    var average_front = 0;
    var average_ebanking = 0;
    $.each(sites, function(s) {
      site = data[sites[s]];

      if (site['role'] == 'front') {

        if (site['ebanking'] != 'app' && site['ebanking'] != 'self') {
          data_set.push({url : sites[s], name: site['bank_name'], hash: MD5(sites[s])});
          var ebanking = data[site['ebanking']];
          build_row(site, sites[s], ebanking);
          
          average_front += site['evaluation']['result'];
          average_ebanking += ebanking['evaluation']['result'];

        } else if(site['ebanking'] == 'self') {
          data_set.push({url : sites[s], name: site['bank_name'], hash: MD5(sites[s])});
          ebanking = site;
          ebanking['role'] = 'ebanking';
          build_row(site, sites[s], ebanking);
          
          average_front += site['evaluation']['result'];
          average_ebanking += ebanking['evaluation']['result'];

        } else if (site['ebanking'] == 'app') {
          //build_row(site, sites[s], {});
        }
      }
    });

    $('#bankers').html(data_set.length);
    $('#average_front').html((average_front/data_set.length).toFixed(2));
    $('#average_ebanking').html((average_ebanking/data_set.length).toFixed(2));

    var search = function(strs) {
      return function findMatches(q, cb) {
        var matches, substrRegex;
        matches = [];
        substrRegex = new RegExp(q, 'i');
        $.each(strs, function(k, v) {
          hash = strs[k];
          if (substrRegex.test(hash['url']) || substrRegex.test(hash['name'])) {
            if (matches.indexOf({value: hash['name'], hash: hash['hash']}) == -1) {
              matches.push({value: hash['name'], hash: hash['hash']});
            }
          }
        });
        cb(matches);
      }
    }

    $('.typeahead').typeahead({
      displayKey: 'val',
      highlight: true,
      hint: true,
      minLength: 3
    },
    {
      name: 'banks',
    source: search(data_set)
    }).on('typeahead:selected', function(e, obj, dataset) {
      location.hash = '#' + obj['hash'];
      $('.typeahead').val('');
    });

    $('button[title="more"]').click(function(e) {
      e.preventDefault();
      $(this).hide();
      var id = $(this).attr('xattr');
      $('button[title="less"][xattr="'+id+'"]').show();
      $('div[xattr="'+id+'"]').show();
    });

    $('button[title="less"]').click(function(e) {
      e.preventDefault();
      $(this).hide();
      var id = $(this).attr('xattr');
      $('button[title="more"][xattr="'+id+'"]').show();
      $('div[xattr="'+id+'"]').hide();
      location.hash = '#'+id ;
    });

  }).done(function() { $('#loading').hide(); });
}).fail(function() {$('#loading').hide();});

function build_row(site, url, ebanking) {

  var evaluation = site['evaluation'];
  // get results from JSON
  site_result = evaluation['result'];
  max_result  = evaluation['max_result'];

  id = MD5(url);
  line = '<section id="'+id+'" >';
  line += '<h2><a name="'+id+'" href="#'+id+'"> '+site['bank_name']+'</a></h2>';
  line += '<ul class="note"><li>'+site_result+'/'+max_result+'</li>';
  // ebanking note
  if (site['ebanking'] != undefined && site['ebanking'] != 'app') {
    eb_result = ebanking['evaluation']['result'];
    line += '<li>'+eb_result+'/'+max_result+'</li>';
  } else {
    line += '<li>—</li>';
  }
  line += '</ul>';
  line += '<ul class="bloc left">';
  // front
  line += build_tile(evaluation, url);
  line += '</ul>';
  line += '<ul class="bloc right">';
  if (site['ebanking'] != undefined && site['ebanking'] != 'app') {
    // ebanking results
    line += build_tile(ebanking['evaluation'], site['ebanking']);
  } else {
    line += '<li><p>— Aucun —</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
  }
  line += '</ul>';
  line += '<div class="postContent hidding" xattr="'+id+'">';
  line += '<ul class="bloc left"><pre>';
  line += build_extended(site);
  line += '</pre></ul>';
  line += '<ul class="bloc right"><pre>';
  if (site['ebanking'] != undefined && site['ebanking'] != 'app') {
    line += build_extended(ebanking);
  }
  line += '</pre></ul>';
  line += '</div>';
  line += '<button class="more" title="more" xattr="'+id+'"></button>';
  line += '<button class="more" title="less" xattr="'+id+'"></button>';
  line += '</section>';

  $('#banks').append(line);
}
function build_tile(evaluation, url) {
  var line;
  if (url == 'self') {
    line = '<li><p>Identique à la banque</p></li>';
  } else {
    line = '<li><p>'+url+'</p></li>';
  }
  if (evaluation['detail']['country'] != undefined) {
    line += '<li><p>'+evaluation['detail']['country']['expl']+'</p></li>';
  } else {
    line += '<li><p>—</p></li>';
  }

  var translation = {
    absent: 'absent',
    forced: 'forcé',
    optional: 'facultatif'
  };



  line += '<li><p>'+translation[evaluation['detail']['ssl']['expl']]+'</p></li>';
  end = new Date(evaluation['detail']['cert']['expl']);
  line += '<li><p>'+end.getDate()+'.'+end.getMonth()+'.'+end.getFullYear()+'</p></li>';
  line += '<li><p>'+evaluation['detail']['server']['expl']+'</p></li>';
  line += '<li><p>'+evaluation['detail']['protocols']['expl'].join(', ')+'</p></li>';

  strong_percent = parseFloat(evaluation['detail']['ciphers']['expl']['strong']).toFixed(1);
  weak_percent   = parseFloat(evaluation['detail']['ciphers']['expl']['weak']).toFixed(1);
  line += '<li><p>'+strong_percent+'% forts, '+weak_percent+'% faibles</p></li>';

  strong_percent = parseFloat(evaluation['detail']['pfs']['strong']).toFixed(1);
  weak_percent   = parseFloat(evaluation['detail']['pfs']['weak']).toFixed(1);
  line += '<li><p>'+strong_percent+'% forts, '+weak_percent+'% faibles</p></li>';
  if (evaluation['detail']['trackers']['expl'] != null) {
    line += '<li><p>'+evaluation['detail']['trackers']['expl'].join(', ')+'</p></li>';
  } else {
    line += '<li><p>—</p></li>';
  }
  if (evaluation['detail']['flash']['points'] != 0) {
    line += '<li><p>Oui</p></li>';
  } else {
    line += '<li><p>—</p></li>';
  }
  if (evaluation['detail']['frames']['expl'] == 'yes' ) {
    if (evaluation['detail']['frames']['points'] == 0) {
      line += '<li><p>Oui, protégées</p></li>';
    } else {
      line += '<li><p>Oui, non protégées</p></li>';
    }
  } else {
    line += '<li><p>—</p></li>';
  }
  return line;
}

function build_extended(site) {

  var ssl_verification = {
    '0':  'ok',
    '2':  "Impossible d'obtenir l'émetteur du certificat",
    '3':  "Impossible d'obtenir le CRL",
    '4':  "Impossible de déchiffrer la signature du certificat",
    '5':  "Impossible de déchiffrer la signature du CRL",
    '6':  "Impossible de déchiffrer la clef publique de l'émetteur",
    '7':  "Erreur de vérification de la signature du certificat",
    '8':  "Erreur de vérification de la signature du CRL",
    '9':  "Le certificat n'est pas encore valide",
    '10': "Le certificat est expiré",
    '11': "CRL pas encore valide",
    '12': "CRL expiré",
    '13': "Erreur de format de date (notBefore) (certificat)",
    '14': "Erreur de format de date (notAfter) (certificat)",
    '15': "Erreur de format de date (lastUpdate) (CRL)",
    '16': "Erreur de format de date (nextUpdate) (CRL)",
    '17': "Out of memory",
    '18': "Certificat auto-signé",
    '19': "Certificat auto-signé dans la chaîne de certificats",
    '20': "Impossible d'obtenir le certificat de l'émetteur local",
    '21': "Impossible de vérifier le premier certificat",
    '22': "Chaîne de certificat trop longue",
    '23': "Certificat révoqué",
    '24': "Certificat CA invalide",
    '25': "path length constraint exceeded",
    '26': "unsupported certificate purpose",
    '27': "Certificat non approuvé",
    '28': "Certificat rejeté",
    '29': "Incompatibilité de sujet émetteur",
    '30': "authority and subject key identifier mismatch",
    '31': "authority and issuer serial number mismatch",
    '32': "key usage does not include certificate signing",
    '50': "application verification failure"
  }



  evaluation = site['evaluation'];

  var line = '<li>Détail de la note<ul>';
  line += '<li>Certificat : '+evaluation['detail']['cert']['points'];
  if (site['certificate'] != undefined && site['certificate']['verify'] != undefined && site['certificate']['verify'] != 0) {
    var i = site['certificate']['verify'];
    line += ' '+ssl_verification[i];
  }
  line += '</li>';
  line += '<li>Ciphers : '+evaluation['detail']['ciphers']['points']+'</li>';
  line += '<li>Pays : '+evaluation['detail']['country']['points']+'</li>';
  line += '<li>Flash : '+evaluation['detail']['flash']['points']+'</li>';
  line += '<li>Frames : '+evaluation['detail']['frames']['points']+'</li>';
  line += '<li>PFS : '+evaluation['detail']['pfs']['points']+'</li>';
  line += '<li>Protocoles : '+evaluation['detail']['protocols']['points']+'</li>';
  line += '<li>SSL : '+evaluation['detail']['ssl']['points']+'</li>';
  line += '<li>Trackers : '+evaluation['detail']['trackers']['points']+'</li>';

  line += '</ul></li>';


  line += '<li>Ciphers supportés : <br>';
  var protos = Object.keys(evaluation['detail']['ciphers']['weak']);
  protos.sort();
  $.each(protos, function(k) {
    proto = protos[k];
    ciphers = evaluation['detail']['ciphers']['weak'][proto];
    line += proto+' (faibles)<ul>';
    $.each(ciphers, function(hash) {
      var pfs = 'avec PFS';
      if (ciphers[hash]['pfs'] == 'no_pfs') {
        pfs = 'sans PFS';
      }
      line += '<li>'+ciphers[hash]['cipher']+' <small><i>'+pfs+'</i></small></li>';
    })
    line += '</ul>';
  });

  protos = Object.keys(evaluation['detail']['ciphers']['strong']);
  protos.sort();
  $.each(protos, function(k) {
    proto = protos[k];
    ciphers = evaluation['detail']['ciphers']['strong'][proto];
    line += proto+' (forts)<ul>';
    $.each(ciphers, function(hash) {
      var pfs = 'avec PFS';
      if (ciphers[hash]['pfs'] == 'no_pfs') {
        pfs = 'sans PFS';
      }
      line += '<li>'+ciphers[hash]['cipher']+' <small><i>'+pfs+'</i></small></li>';
    })
    line += '</ul>';
  });

  line += 'Informations IP:<ul>';
  line += '</ul>';
  $.each(site['ips'], function(ip) {
    line += '<li>'+ip+'<ul>';
    ip_elements = Object.keys(site['ips'][ip]);
    ip_elements.sort();
    $.each(ip_elements, function(k) {
      var el = ip_elements[k]
      if (
        el.toLowerCase() == 'country' ||
        el.toLowerCase() == 'mnt-by'  ||
        el.toLowerCase() == 'admin-c' ||
        el.toLowerCase() == 'descr'   ||
        el.toLowerCase() == 'netname' ||
        el.toLowerCase() == 'role'    ||
        el.toLowerCase() == 'org-name'||
        el.toLowerCase() == 'org'
        ) {
          v = site['ips'][ip][el];
          line += '<li>'+el+': '+v+'</li>';
        }
    });
    line += '</ul></li>';
  });

  line += '</li>';

  return line;
}
