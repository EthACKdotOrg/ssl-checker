$.getJSON('/jsons/index.json', function(data) {
  // get latest generated JSON
  var latest = data[data.length-1];
  $('#update').html(latest);

  $.getJSON("/jsons/"+latest+".json", function(data) {
    var sites = Object.keys(data['banks']);
    var data_set = new Array();
    sites.sort();
    var average_front = 0;
    var average_ebanking = 0;
    var max_grade = 0;
    $.each(sites, function(s) {

      var site = data['banks'][sites[s]];
      var front = site['frontend'];
      var back  = site['backend'];

      if (site['backend'] != 'app' && site['backend'] != 'self') {
        data_set.push({name: sites[s], hash: MD5(sites[s])});
        build_row(site, sites[s]);
        
        if (site['results'][front] != undefined) {
          average_front += site['results'][front]['grades']['total'];
          max_grade = site['results'][front]['grades']['max'];
        }
        if (site['results'][back] != undefined) {
          average_ebanking += site['results'][back]['grades']['total'];
        }

      } else if(site['backend'] == 'self') {
        data_set.push({name: sites[s], hash: MD5(sites[s])});
        build_row(site, sites[s]);
 
        if (site['results'][front] != undefined) {
          average_front += site['results'][front]['grades']['total'];
          average_ebanking += site['results'][front]['grades']['total'];
        }

      } else if (site['backend'] == 'app') {
        //build_row(site, sites[s], {});
      }
    });

    $('#bankers').html(data_set.length);
    $('#average_front').html((average_front/data_set.length).toFixed(2));
    $('#average_ebanking').html((average_ebanking/data_set.length).toFixed(2));
    $('#max_grade').html(max_grade);

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
}).fail(function() {
  $('#loading').hide();
  console.log('Error while loading json');
});

function build_row(site, bank_name) {

  frontend = site['frontend'];
  backend  = site['backend'];
  id       = MD5(bank_name);
  var eval_front;
  var eval_back

  line = '<section id="'+id+'" >';
  line += '<h2><a name="'+id+'" href="#'+id+'"> '+bank_name+'</a></h2>';
  line += '<ul class="note">';
  // do we have some frontend results?
  if (site['results'][frontend] != undefined) {
    eval_front = site['results'][frontend];
    site_result = eval_front['grades']['total'];
    max_result  = eval_front['grades']['max'];

    line += '<li>'+site_result+'/'+max_result+'</li>';
  } else {
    line += '<li>—</li>';
  }
  // ebanking note
  if (site['results'][backend] != undefined && backend != 'app') {
    eval_back = site['results'][backend];
    eb_result  = eval_back['grades']['total'];
    max_result = eval_back['grades']['max'];
    line += '<li>'+eb_result+'/'+max_result+'</li>';
  } else if(backend == 'self') {
    eval_front = site['results'][frontend];
    if (eval_front != undefined) {
      site_result = eval_front['grades']['total'];
      max_result  = eval_front['grades']['max'];
      line += '<li>'+site_result+'/'+max_result+'</li>';
    } else {
      line += '<li>—</li>';
      console.log(bank_name);
    }
  } else {
    line += '<li>—</li>';
    console.log(bank_name);
  }
  line += '</ul>';
  line += '<ul class="bloc left">';
  // front
  if (site['results'][frontend] != undefined) {
    line += build_tile(eval_front, frontend);
  } else {
    line += '<li><p>'+frontend+'</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>Non</p></li>';
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
  // ebanking results
  line += '<ul class="bloc right">';
  if (site['results'][backend] != undefined && backend != 'app') {
    line += build_tile(eval_back, backend);
  } else if (backend == 'self') {
    line += build_tile(eval_front, frontend);
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
  line += build_extended(site);
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

  if (evaluation != undefined) {
    line += '<li><p>'+evaluation.country.ip+'</p></li>';

    if (evaluation['key'] != undefined) {
      if (evaluation['response']['force_ssl'] == 1) {
        line += '<li><p>Oui, forcé</p></li>';
      } else if(evaluation['response']['force_ssl'] == 2) {
        line += '<li><p>Oui, uniquement</p></li>';
      } else {
        line += '<li><p>Oui, facultatif</p></li>';
      }
    } else {
      line += '<li><p>Absent</p></li>';
    }
    if (evaluation['key'] != undefined) {
      end = new Date(evaluation['key']['notAfter']);
      line += '<li><p>'+end.getDate()+'.'+end.getMonth()+'.'+end.getFullYear()+'</p></li>';
    } else {
      line += '<li><p>—</p></li>';
    }
    if (evaluation.key.ocspStapling == 0) {
      line += '<li><p>Non</p></li>';
    } else {
      line += '<li><p>Oui</p></li>';
    }
    var proto = evaluation['protocols']
    line += '<li><p>'+evaluation['protocols']['enabled'].join(', ')+'</p></li>';

    var preferred = new Array();
    $.each(evaluation['preferredCiphers'], function(proto, data) {
      if (data['name'] != null) {
        preferred.push(data['name']);
      }
    });
    line += '<li><p></p><ul><li>'+preferred.join('</li><li>')+'</li></ul></li>';
    if (evaluation.response.hsts != '') {
      line += '<li><p>Oui ('+evaluation.response.hsts+')</p></li>';
    } else {
      line += '<li><p>Non</p></li>';
    }

    if (evaluation['trackers'].length != 0) {
      line += '<li><p>'+evaluation['trackers'].join(', ')+'</p></li>';
    } else {
      line += '<li><p>—</p></li>';
    }
    if (evaluation['response']['flash'] != 0) {
      line += '<li><p>Oui</p></li>';
    } else {
      line += '<li><p>—</p></li>';
    }
    if (evaluation['response']['frame'] == 1 ) {
      if (evaluation['response']['xframeopt'] != '') {
        line += '<li><p>Oui, protégées</p></li>';
      } else {
        line += '<li><p>Oui, non protégées</p></li>';
      }
    } else {
      line += '<li><p>—</p></li>';
    }
  } else {
    console.log(url);
    line += '<li><p>—</p></li>';
    line += '<li><p>Non</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
  }
  return line;
}

function build_extended(site) {

  var frontend = site['frontend'];
  var backend  = site['backend'];

  var front_tile;

  line  = '<ul class="bloc left"><pre>';
  // front
  if (site['results'][frontend] != undefined) {
    front_tile = build_extra_tile(site['results'][frontend])
  } else {
    front_tile = 'Aucune information';
  }
  line += front_tile;
  line += '</pre></ul>';
  line += '<ul class="bloc right"><pre>';
  if (site['results'][backend] != undefined && site['results'][backend] != 'app') {
    // backend
    line += build_extra_tile(site['results'][backend]);
  } else if (backend != undefined && backend == 'self') {
    line += front_tile;
  } else {
    line += 'Aucune information';
  }
  line += '</pre></ul>';

  return line;
}

function build_extra_tile(site) {
  var grades = site.grades;

  var type = {
    'id-ecPublicKey': 'ECC',
    'rsaEncryption': 'RSA',
    'sha256WithRSAEncryption': 'SHA2',
    'sha1WithRSAEncryption': 'SHA1'
  };

  var line = '<li>Détail de la note<ul>';
  line += '<li>Certificat (commonName) : '+grades.cert_match+'</li>';
  line += '<li>Certificat (échéance) : '+grades.cert_validity+'</li>';
  line += '<li>Ciphers : '+grades.ciphers+'</li>';
  line += '<li>Flash : '+grades.flash+'</li>';
  line += '<li>Frame : '+grades.frames+'</li>';
  line += '<li>HSTS : '+grades.hsts+'</li>';
  line += '<li>OCSP Stapling : '+grades.ocsp_stapling+'</li>';
  line += '<li>Protocoles : '+grades.protocols+'</li>';
  line += '<li>Redirection SSL : '+grades.enforce_ssl+'</li>';
  line += '<li>Signature : '+grades.signature+' ('+ type[site.key.signatureAlgorithm] +')</li>';
  line += '<li>Taille de la clef : '+grades.keysize+' ('+site.key.keySize+')</li>';
  line += '<li>Trackers : '+grades.trackers+'</li>';
  line += '</ul>';

  line += '</li>';
  return line;
}
