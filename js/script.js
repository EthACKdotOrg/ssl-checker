$.getJSON("./output.json", function(data) {
  var sites = Object.keys(data);
  var data_set = new Array();
  sites.sort();
  $.each(sites, function(s) {
    site = data[sites[s]];

    if (site['role'] == 'front') {
      data_set.push({url : sites[s], name: site['bank_name'], hash: MD5(sites[s])});

      if (site['ebanking'] != 'app' && site['ebanking'] != 'self') {
        var ebanking = data[site['ebanking']];
        build_row(site, sites[s], ebanking);
      } else if(site['ebanking'] == 'self') {
        ebanking = site;
        ebanking['role'] = 'ebanking';
        build_row(site, sites[s], ebanking);
      } else if (site['ebanking'] == 'app') {
        build_row(site, sites[s], {});
      }
    }
  });

  $('#bankers').html(data_set.length);
  $('#update').html(data['date']);

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
  });

}).done(function() { $('#loading').hide(); });


function build_row(site, url, ebanking) {

  var evaluation = site['evaluation'];
  // get results from JSON
  site_result = evaluation['result'];
  max_result  = evaluation['max_result'];

  id = MD5(url);
  line = '<section id="'+id+'" >';
  line += '<h2><a name="'+id+'" href="#'+id+'"> '+site['bank_name']+'</a></h2>';
  line += '<ul class="note"><li>'+site_result+'/'+max_result+'</li>';
  // TODO: ebanking note
  line += '</ul>';
  line += '<ul class="bloc left">';
  // TODO: front
  line += build_tile(evaluation, url);
  line += '</ul>';
  line += '<ul class="bloc right">';
  if (site['ebanking'] != 'app') {
    // TODO: ebanking results
    line += build_tile(ebanking['evaluation'], site['ebanking']);
  } else {
    line += '<li><p>Application dédiée</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
    line += '<li><p>—</p></li>';
  }
  line += '</ul>';
  line += '<button class="more" title="more" xattr="'+id+'"></button>';
  line += '<button class="more" title="less" xattr="'+id+'"></button>';
  line += '<div class="postContent hidding" xattr="'+id+'">';
  line += '<ul class="bloc left">';
  line += build_extended(site);
  line += '</ul>';
  line += '<ul class="bloc right">';
  if (site['ebanking'] != 'app') {
    line += build_extended(ebanking);
  }
  line += '</ul>';
  line += '</div>';
  line += '</section>';

  $('#banks').append(line);
}
function build_tile(evaluation, url) {
  line = '<li><p>'+url+'</p></li>';
  if (evaluation['detail']['country'] != undefined) {
    line += '<li><p>'+evaluation['detail']['country']['expl']['module']+'</p></li>';
  } else {
    line += '<li><p>—</p></li>';
  }
  line += '<li><p>'+evaluation['detail']['ssl']['expl']+'</p></li>';
  end = new Date(evaluation['detail']['cert']['expl']);
  line += '<li><p>'+end.getDate()+'.'+end.getMonth()+'.'+end.getFullYear()+'</p></li>';
  line += '<li><p>'+evaluation['detail']['server']['expl']+'</p></li>';
  line += '<li><p>'+evaluation['detail']['protocols']['expl'].join(', ')+'</p></li>';
  line += '<li><p></p></li>';
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
    if (evaluation['detail']['frames']['points']) {
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
  evaluation = site['evaluation'];
  var line = '<li>Ciphers supportés ('+evaluation['detail']['ciphers']['points']+' points): <br>';
  $.each(evaluation['detail']['ciphers']['weak'], function(proto, ciphers) {
    line += proto+' (faibles)<ul>';
    $.each(ciphers, function(hash) {
      var pfs = 'PFS supporté';
      if (ciphers[hash]['pfs'] == 'no_pfs') {
        pfs = 'PFS non supporté';
      }
      line += '<li>'+ciphers[hash]['cipher']+' ('+pfs+')</li>';
    })
    line += '</ul>';
  });
  $.each(evaluation['detail']['ciphers']['strong'], function(proto, ciphers) {
    line += proto+' (forts)<ul>';
    $.each(ciphers, function(hash) {
      var pfs = 'PFS supporté';
      if (ciphers[hash]['pfs'] == 'no_pfs') {
        pfs = 'PFS non supporté';
      }
      line += '<li>'+ciphers[hash]['cipher']+' ('+pfs+')</li>';
    })
    line += '</ul>';
  });

  line += 'Informations IP:<ul>';
  line += '</ul>';
  $.each(site['ips'], function(ip) {
    line += '<li>'+ip+'<ul>';
    $.each(site['ips'][ip], function(k, v) {
      if (k.toLowerCase() != '% note' && k.toLowerCase() != 'remarks') {
        line += '<li>'+k+': '+v+'</li>';
      }
    });
    line += '</ul></li>';
  });

  line += '</li>';

  return line;
}
