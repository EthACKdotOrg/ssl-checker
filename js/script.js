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

  site_result = build_tile(site, url);
  ebank_result = new Array();
  if (ebanking['ips'] != undefined) {
    eb_site = site['ebanking'];
    if (site['ebanking'] == 'self') {
      eb_site = url;
    }
    ebank_result = build_tile(ebanking, eb_site);
  }
  id = MD5(url);
  line = '<section id="'+id+'" >';
  line += '<h2><a name="'+id+'" href="#'+id+'"> '+site['bank_name']+'</a></h2>';
  line += '<ul class="note"><li>'+site_result[1]+'/'+site_result[2]+'</li>';
  if (ebank_result.length > 0) {
    line += '<li>'+ebank_result[1]+'/'+ebank_result[2]+'</li>';
  } else {
    line += '<li>—</li>';
  }
  line += '</ul>';
  line += '<ul class="bloc left">';
  line += site_result[0];
  line += '</ul>';
  line += '<ul class="bloc right">';
  if (ebank_result[0] != undefined) {
    line += ebank_result[0];
  } else {
    line += '<li><p>Application dédiée</p></li>';
    line += '<li><p></p></li>';
    line += '<li><p></p></li>';
    line += '<li><p></p></li>';
    line += '<li><p></p></li>';
    line += '<li><p></p></li>';
    line += '<li><p></p></li>';
  }
  line += '</ul>';
  line += '<button class="more" title="more" xattr="'+id+'"></button>';
  line += '<button class="more" title="less" xattr="'+id+'"></button>';
  line += '<div class="postContent hidding" xattr="'+id+'">';
  line += '<ul class="bloc left"> blah';
  line += '</ul>';
  line += '<ul class="bloc right"> blah';
  line += '</ul>';
  line += '</div>';
  line += '</section>';

  $('#banks').append(line);
}

function build_tile(site, url) {
  result = 0;
  result_max = 0;
  // display web site URL
  server_info = site['server_info'][(site['server_info'].length-1)];

  // where is it hosted?
  var bg_country = 'warning';
  var country;
  $.each(site['ips'], function(address, hash) {
    if (hash['country'] != undefined) {
      country = hash['country'];
    } else if (hash['Country'] != undefined) {
      country = hash['Country'];
    }
  });
  if (
      country == 'UNITED STATES' ||
      country == 'USA' ||
      country == 'US' ||
      country == 'UK' ||
      country == 'GB' ||
      country == 'UNITED KINGDOM') {
        bg_country = 'danger';
      } else if(country == 'SWITZERLAND' || country == 'CH') {
        bg_country = 'success';
        result += 2;
      } else {
        result += 1;
      }
  result_max += 2;

  var ips = Object.keys(site['ips']).join(', ');

  // does it support SSL?
  var ssl_support;
  if (site['protocols'].length > 0) {
    if (site['no_ssl']['clear_access'] == 'yes') {
      if (server_info['target'].match(/^https:\/\//i)) {
        ssl_support = '<i class="fa fa-lock"></i> oui, redirigé'
        result += 2;
      } else {
        ssl_support = '<i class="fa fa-lock"></i> facultatif';
        result += 1;
      }
    } else {
      ssl_support = '<i class="fa fa-lock"></i> uniquement';
      result += 2;
    }
  } else {
    ssl_suppport = '<i class="fa fa-unlock"></i> non-disponible';
  }
  result_max += 2;

  // server type
  var server = '-';
  if (server_info['plugins']['HTTPServer'] != undefined && 
      server_info['plugins']['HTTPServer']['string'][0] != '') {
    server = server_info['plugins']['HTTPServer']['string'][0];
  }

  if (site['protocols'].length == 0) {
    bg = 'danger';
    protos = 'aucun';
  } else {
    if (site['protocols'].indexOf('SSLv3') != -1) {
      if (site['protocols'].length < 3) {
        bg = 'danger';
      } else {
        bg = 'warning';
        result += 1;
      }
    } else if(site['protocols'].length == 1 && site['protocols'].indexOf('TLSv1') != -1) {
      bg = 'warning';
      result += 1;
    } else {
      bg = 'success';
      result += 2;
    }
    protos = site['protocols'].join(', ');
  }
  result_max += 2;

  var cipher_support;
  if (site['protocols'].length > 0) {
    var weak = get_ciphers(site['ciphers'], 'weak');
    var strong = get_ciphers(site['ciphers'], 'good');
    ponderation = (27*100/30);
    percent_weak = ((weak[0].length*ponderation/27)).toFixed(1);
    percent_strong = ((strong[0].length*100/30)).toFixed(1);

    if (parseInt(percent_weak) < parseInt(percent_strong)) {
      result += 2;
    }

    cipher_support = percent_strong+'% forts, ';
    cipher_support += percent_weak+'% faibles';
  } else {
    result -=1;
  }
  result_max += 2;

  var pfs_support;
  if (site['protocols'].length > 0) {
    pfs_ponderation = (2*100/24);
    percent_weak_pfs = ((weak[1]*pfs_ponderation/2)).toFixed(1);
    percent_strong_pfs = ((strong[1]*100/24)).toFixed(1);
    if (parseInt(percent_weak_pfs) < parseInt(percent_strong_pfs)) {
      if (parseInt(percent_strong_pfs) > 60) {
        result += 2;
      } else {
        result += 1;
      }
    }
    pfs_support = percent_strong_pfs+'% forts, ';
    pfs_support += percent_weak_pfs+'% faibles';
  } else {
  }
  result_max += 2;

  // trackers: remove points.
  var trackers = new Array();
  var tracking = false;
  if (server_info['plugins']['Google-Analytics'] != undefined) {
    if (site['role'] == 'ebanking') {
      result -= 2;
    } else {
      result -= 1;
    }
    trackers.push('Google Analytics');
    tracking = true;
  }

  if (server_info['plugins']['Google-API'] != undefined) {
    if (site['role'] == 'ebanking') {
      result -= 2;
    } else {
      result -= 1;
    }
    trackers.push('Google API');
    tracking = true;
  }

  // Flash - remove point!
  var flash = false;
  if (server_info['plugins']['Adobe-Flash'] != undefined) {
    if (site['role'] == 'ebanking') {
      result -= 2;
    } else {
      result -= 1;
    }
    flash = true;
  }

  // Frame? If so, X-Frame-Options?
  var framed = false;
  var locked_frame = true;
  if (server_info['plugins']['Frame'] != undefined) {
    framed = true;
    if (server_info['plugins']['X-Frame-Options'] != undefined) {
      if (server_info['plugins']['X-Frame-Options']['string'].indexOf('SAMEORIGIN') != -1) {
        locked_frame = true;
      } else {
        if (site['role'] == 'ebanking') {
          result -= 2;
        } else {
          result -= 1;
        }
        locked_frame = false;
      }
    } else {
      if (site['role'] == 'ebanking') {
        result -= 2;
      } else {
        result -= 1;
      }
      locked_frame = false;
    }
  }

  // Heartbleed: announced April 1, 2014 — has the SSL certificate been changed right after?
  // NOTA: unable to know if server were really affected — so far, apache/nginx were, Windows stuff wasn't.
  // Also, if they "re-keyed", the certificate validity doesn't change…
  var certificate = '—';
  if (site['certificate']['not_before'] != undefined) {
    var start = new Date(site['certificate']['not_before']);
    var end = new Date(site['certificate']['not_after']);
    certificate = 'du '+start.getDate()+'.'+start.getMonth()+'.'+start.getFullYear();
    certificate += ' au '+end.getDate()+'.'+end.getMonth()+'.'+end.getFullYear();

    var now = new Date();
    if (end.getTime() < now.getTime()) {
      if (site['role'] == 'ebanking') {
        result -= 2;
      } else {
        result -= 1;
      }
    }
  }



  line = '<li><p>'+url+'</p></li>';
  line += '<li><p>'+country+' ('+ips+')</p></li>';
  if (ssl_support != undefined) {
    line += '<li><p>'+ssl_support+'</p></li>';
  } else {
    line += '<li><p>non</p></li>';
  }
  line += '<li><p>'+certificate+'</p></li>';
  line += '<li><p>'+server+'</p></li>';
  if (site['protocols'] != undefined && site['protocols'].length > 0) {
    line += '<li><p>'+site['protocols'].join(', ')+'</p></li>';
  } else {
    line += '<li><p>aucun</p></li>';
  }
  if (cipher_support != undefined) {
    line += '<li><p>'+cipher_support+'</p></li>';
  } else {
    line += '<li><p>aucun</p></li>';
  }
  if (pfs_support != undefined) {
    line += '<li><p>'+pfs_support+'</p></li>';
  } else {
    line += '<li><p>aucun</p></li>';
  }
  if (tracking) {
    line += '<li><p>'+trackers.length+' script(s)</p></li>';
  } else {
    line += '<li><p>aucun</p></li>';
  }
  if (flash) {
    line += '<li><p>oui</p></li>';
  } else {
    line += '<li><p>non</p></li>';
  }

  if (framed) {
    if (locked_frame) {
      line += '<li><p>Oui, protégées</p></li>';
    } else {
      line += '<li><p>Oui, NON protégées</p></li>';
    }
  } else {
    line += '<li><p>non</p></li>';
  }

  return new Array(line, result, result_max);
}
function merge_ciphers(ssl3, tls1, tls11, tls12) {
  unique = new Array();
  pfs = 0;
  $.each(ssl3, function(key, hash) {
    cipher = hash['cipher'];
    if(unique.indexOf(cipher) == -1) { unique.push(cipher); if (hash['pfs'] == 'pfs') { pfs+=1;}}
  });
  $.each(tls1, function(key, hash) {
    cipher = hash['cipher'];
    if(unique.indexOf(cipher) == -1) { unique.push(cipher); if (hash['pfs'] == 'pfs') { pfs+=1;}}
  });
  $.each(tls11, function(key, hash) {
    cipher = hash['cipher'];
    if(unique.indexOf(cipher) == -1) { unique.push(cipher); if (hash['pfs'] == 'pfs') { pfs+=1;}}
  });
  $.each(tls12, function(key, hash) {
    cipher = hash['cipher'];
    if(unique.indexOf(cipher) == -1) { unique.push(cipher); if (hash['pfs'] == 'pfs') { pfs+=1;}}
  });
  return new Array(unique, pfs);
}
function get_ciphers(hash, level) {
  ssl3 = [];
  tls1 = [];
  tls11 = [];
  tls12 = [];
  if (hash[level] != undefined) {
    if (hash['weak']['SSLv3'] != undefined) {
      ssl3 = hash[level]['SSLv3'];
    }
    if (hash[level]['TLSv1'] != undefined) {
      tls1 = hash[level]['TLSv1'];
    }
    if (hash[level]['TLSv11'] != undefined) {
      tls11 = hash[level]['TLSv11'];
    }
    if (hash[level]['TLSv12'] != undefined) {
      tls12 = hash[level]['TLSv12'];
    }
  }
  return merge_ciphers(ssl3, tls1, tls11, tls12);
}
