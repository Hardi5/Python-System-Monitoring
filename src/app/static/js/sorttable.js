/*
  SortTable
  version 2
  7th April 2007
  Stuart Langridge, http://www.kryogenix.org/code/browser/sorttable/

  Instructions:
  Download this file
  Add <script src="sorttable.js"></script> to your HTML
  Add class="sortable" to any table you'd like to make sortable
  Click on the headers to sort

  Thanks to many, many people for contributions and suggestions.
  Licenced as X11: http://www.kryogenix.org/code/browser/licence.html
  This basically means: do what you want with it.
*/

const stIsIE = /*@cc_on!@*/false;

const sorttable = {
  init: function() {
    // quit if this function has already been called
    if (sorttable.init.done) return;
    // flag this function so we don't do the same thing twice
    sorttable.init.done = true;
    // kill the timer
    if (_timer) clearInterval(_timer);

    if (!document.createElement || !document.getElementsByTagName) return;

    sorttable.DATE_RE = /^(\d\d?)[\/\.-](\d\d?)[\/\.-]((\d\d)?\d\d)$/;

    forEach(document.getElementsByTagName('table'), function(table) {
      if (table.className.search(/\bsortable\b/) != -1) {
        sorttable.makeSortable(table);
      }
    });

  },

  makeSortable: function(table) {
    if (table.getElementsByTagName('thead').length === 0) {
      // table doesn't have a tHead. Since it should have, create one and
      // put the first table row in it.
      const the = document.createElement('thead');
      the.appendChild(table.rows[0]);
      table.insertBefore(the, table.firstChild);
    }
    // Safari doesn't support table.tHead, sigh
    if (table.tHead === null) table.tHead = table.getElementsByTagName('thead')[0];

    if (table.tHead.rows.length !== 1) return; // can't cope with two header rows

    // Sorttable v1 put rows with a class of "sortbottom" at the bottom (as
    // "total" rows, for example). This is B&R, since what you're supposed
    // to do is put them in a tfoot. So, if there are sortbottom rows,
    // for backwards compatibility, move them to tfoot (creating it if needed).
    const sortbottomrows = [];
    for (let i = 0; i < table.rows.length; i++) {
      if (table.rows[i].className.search(/\bsortbottom\b/) != -1) {
        sortbottomrows.push(table.rows[i]);
      }
    }
    if (sortbottomrows.length) {
      let tfo;
      if (table.tFoot === null) {
        // table doesn't have a tfoot. Create one.
        tfo = document.createElement('tfoot');
        table.appendChild(tfo);
      }
      for (let i = 0; i < sortbottomrows.length; i++) {
        tfo.appendChild(sortbottomrows[i]);
      }
    }

    // work through each column and calculate its type
    const headrow = table.tHead.rows[0].cells;
    for (let i = 0; i < headrow.length; i++) {
      // manually override the type with a sorttable_type attribute
      if (!headrow[i].className.match(/\bsorttable_nosort\b/)) { // skip this col
        const mtch = headrow[i].className.match(/\bsorttable_([a-z0-9]+)\b/);
        let override;
        if (mtch) { override = mtch[1]; }
        if (mtch && typeof sorttable["sort_" + override] === 'function') {
          headrow[i].sorttable_sortfunction = sorttable["sort_" + override];
        } else {
          headrow[i].sorttable_sortfunction = sorttable.guessType(table, i);
        }
        // make it clickable to sort
        headrow[i].sorttable_columnindex = i;
        headrow[i].sorttable_tbody = table.tBodies[0];
        dean_addEvent(headrow[i], "click", function() {

          if (this.className.search(/\bsorttable_sorted\b/) != -1) {
            // if we're already sorted by this column, just
            // reverse the table, which is quicker
            sorttable.reverse(this.sorttable_tbody);
            this.className = this.className.replace('sorttable_sorted',
              'sorttable_sorted_reverse');
            this.removeChild(document.getElementById('sorttable_sortfwdind'));
            const sortrevind = document.createElement('span');
            sortrevind.id = "sorttable_sortrevind";
            sortrevind.innerHTML = stIsIE ? '&nbsp<font face="webdings">5</font>' : '&nbsp;&#x25B4;';
            this.appendChild(sortrevind);
            return;
          }
          if (this.className.search(/\bsorttable_sorted_reverse\b/) != -1) {
            // if we're already sorted by this column in reverse, just
            // re-reverse the table, which is quicker
            sorttable.reverse(this.sorttable_tbody);
            this.className = this.className.replace('sorttable_sorted_reverse',
              'sorttable_sorted');
            this.removeChild(document.getElementById('sorttable_sortrevind'));
            const sortfwdind = document.createElement('span');
            sortfwdind.id = "sorttable_sortfwdind";
            sortfwdind.innerHTML = stIsIE ? '&nbsp<font face="webdings">6</font>' : '&nbsp;&#x25BE;';
            this.appendChild(sortfwdind);
            return;
          }

          // remove sorttable_sorted classes
          const theadrow = this.parentNode;
          forEach(theadrow.childNodes, function(cell) {
            if (cell.nodeType === 1) { // an element
              cell.className = cell.className.replace('sorttable_sorted_reverse', '');
              cell.className = cell.className.replace('sorttable_sorted', '');
            }
          });
          let sortfwdind = document.getElementById('sorttable_sortfwdind');
          if (sortfwdind) { sortfwdind.parentNode.removeChild(sortfwdind); }
          let sortrevind = document.getElementById('sorttable_sortrevind');
          if (sortrevind) { sortrevind.parentNode.removeChild(sortrevind); }

          this.className += ' sorttable_sorted';
          sortfwdind = document.createElement('span');
          sortfwdind.id = "sorttable_sortfwdind";
          sortfwdind.innerHTML = stIsIE ? '&nbsp<font face="webdings">6</font>' : '&nbsp;&#x25BE;';
          this.appendChild(sortfwdind);

          // build an array to sort. This is a Schwartzian transform thing,
          // i.e., we "decorate" each row with the actual sort key,
          // sort based on the sort keys, and then put the rows back in order
          // which is a lot faster because you only do getInnerText once per row
          let row_array = [];
          const col = this.sorttable_columnindex;
          const rows = this.sorttable_tbody.rows;
          for (let j = 0; j < rows.length; j++) {
            row_array.push([sorttable.getInnerText(rows[j].cells[col]), rows[j]]);
          }
          /* If you want a stable sort, uncomment the following line */
          //sorttable.shaker_sort(row_array, this.sorttable_sortfunction);
          /* and comment out this one */
          row_array.sort(this.sorttable_sortfunction);
          row_array.reverse();

          const tb = this.sorttable_tbody;
          for (let j = 0; j < row_array.length; j++) {
            tb.appendChild(row_array[j][1]);
          }

        });
      }
    }
  },

  guessType: function(table, column) {
    // guess the type of a column based on its first non-blank row
    let sortfn = sorttable.sort_alpha;
    for (let i = 0; i < table.tBodies[0].rows.length; i++) {
      const text = sorttable.getInnerText(table.tBodies[0].rows[i].cells[column]);
      if (text !== '') {
        if (text.match(/^-?[£$€]?[\d,.]+%?$/)) {
          return sorttable.sort_numeric;
        }
        // check for a date: dd/mm/yyyy or dd/mm/yy
        // can have / or . or - as separator
        // can be mm/dd as well
        const possdate = text.match(sorttable.DATE_RE)
        if (possdate) {
          // looks like a date
          const first = parseInt(possdate[1]);
          const second = parseInt(possdate[2]);
          if (first > 12) {
            // definitely dd/mm
            return sorttable.sort_ddmm;
          } else if (second > 12) {
            return sorttable.sort_mmdd;
          } else {
            // looks like a date, but we can't tell which, so assume
            // that it's dd/mm (English imperialism!) and keep looking
            sortfn = sorttable.sort_ddmm;
          }
        }
      }
    }
    return sortfn;
  },

  getInnerText: function(node) {
    if (!node) return "";

    const hasInputs = (typeof node.getElementsByTagName === 'function') &&
      node.getElementsByTagName('input').length;

    if (node.getAttribute("sorttable_customkey") != null) {
      return node.getAttribute("sorttable_customkey");
    }
    else if (typeof node.textContent !== 'undefined' && !hasInputs) {
      return node.textContent.trim();
    }
    else if (typeof node.innerText !== 'undefined' && !hasInputs) {
      return node.innerText.trim();
    }
    else if (typeof node.text !== 'undefined' && !hasInputs) {
      return node.text.trim();
    }
    else {
      switch (node.nodeType) {
        case 3:
          if (node.nodeName.toLowerCase() === 'input') {
            return node.value.trim();
          }
          // Missing break statement added
          break;
        case 4:
          return node.nodeValue.trim();
        case 1:
        case 11:
          let innerText = '';
          for (let i = 0; i < node.childNodes.length; i++) {
            innerText += sorttable.getInnerText(node.childNodes[i]);
          }
          return innerText.trim();
        default:
          return '';
      }
    }
  },

  reverse: function(tbody) {
    // reverse the rows in a tbody
    const newrows = [];
    for (let i = 0; i < tbody.rows.length; i++) {
      newrows.push(tbody.rows[i]);
    }
    for (let i = newrows.length - 1; i >= 0; i--) {
      tbody.appendChild(newrows[i]);
    }
  },

  /* sort functions
     each sort function takes two parameters, a and b
     you are comparing a[0] and b[0] */
  sort_numeric: function(a, b) {
    let aa = parseFloat(a[0].replace(/[^0-9.-]/g, ''));
    let bb = parseFloat(b[0].replace(/[^0-9.-]/g, ''));
    if (isNaN(aa)) aa = 0;
    if (isNaN(bb)) bb = 0;
    return aa - bb;
  },
  sort_alpha: function(a, b) {
    if (a[0] === b[0]) return 0;
    return a[0] < b[0] ? -1 : 1;
  },
  sort_ddmm: function(a, b) {
    const mtchA = a[0].match(sorttable.DATE_RE);
    const yA = mtchA[3]; const mA = mtchA[2]; const dA = mtchA[1];
    const dt1 = `${yA}${mA.padStart(2, '0')}${dA.padStart(2, '0')}`;
    const mtchB = b[0].match(sorttable.DATE_RE);
    const yB = mtchB[3]; const mB = mtchB[2]; const dB = mtchB[1];
    const dt2 = `${yB}${mB.padStart(2, '0')}${dB.padStart(2, '0')}`;
    return dt1.localeCompare(dt2);
  },
  sort_mmdd: function(a, b) {
    const mtchA = a[0].match(sorttable.DATE_RE);
    const yA = mtchA[3]; const dA = mtchA[2]; const mA = mtchA[1];
    const dt1 = `${yA}${mA.padStart(2, '0')}${dA.padStart(2, '0')}`;
    const mtchB = b[0].match(sorttable.DATE_RE);
    const yB = mtchB[3]; const dB = mtchB[2]; const mB = mtchB[1];
    const dt2 = `${yB}${mB.padStart(2, '0')}${dB.padStart(2, '0')}`;
    return dt1.localeCompare(dt2);
  },

  shaker_sort: function(list, comp_func) {
    // A stable sort function to allow multi-level sorting of data
    // see: http://en.wikipedia.org/wiki/Cocktail_sort
    // thanks to Joseph Nahmias
    let b = 0;
    let t = list.length - 1;
    let swap = true;

    while (swap) {
      swap = false;
      for (let i = b; i < t; ++i) {
        if (comp_func(list[i], list[i + 1]) > 0) {
          const q = list[i]; list[i] = list[i + 1]; list[i + 1] = q;
          swap = true;
        }
      } // for
      t--;

      if (!swap) break;

      for (let i = t; i > b; --i) {
        if (comp_func(list[i], list[i - 1]) < 0) {
          const q = list[i]; list[i] = list[i - 1]; list[i - 1] = q;
          swap = true;
        }
      } // for
      b++;

    } // while(swap)
  }
}

/* ******************************************************************
   Supporting functions: bundled here to avoid depending on a library
   ****************************************************************** */

// Dean Edwards/Matthias Miller/John Resig

/* for Mozilla/Opera9 */
if (document.addEventListener) {
  document.addEventListener("DOMContentLoaded", sorttable.init, false);
}

/* for Internet Explorer */
/*@cc_on @*/
/*@if (@_win32)
    document.write("<script id=__ie_onload defer src=javascript:void(0)><\/script>");
    const script = document.getElementById("__ie_onload");
    script.onreadystatechange = function() {
        if (this.readyState == "complete") {
            sorttable.init(); // call the onload handler
        }
    };
/*@end @*/

/* for Safari */
if (/WebKit/i.test(navigator.userAgent)) { // sniff
  var _timer = setInterval(function() {
    if (/loaded|complete/.test(document.readyState)) {
      sorttable.init(); // call the onload handler
    }
  }, 10);
}

/* for other browsers */
window.onload = sorttable.init;

// written by Dean Edwards, 2005
// with input from Tino Zijdel, Matthias Miller, Diego Perini

// http://dean.edwards.name/weblog/2005/10/add-event/

function dean_addEvent(element, type, handler) {
  if (element.addEventListener) {
    element.addEventListener(type, handler, false);
  } else {
    // assign each event handler a unique ID
    if (!handler.$$guid) handler.$$guid = dean_addEvent.guid++;
    // create a hash table of event types for the element
    if (!element.events) element.events = {};
    // create a hash table of event handlers for each element/event pair
    const handlers = element.events[type];
    if (!handlers) {
      element.events[type] = {};
      // store the existing event handler (if there is one)
      if (element["on" + type]) {
        element.events[type][0] = element["on" + type];
      }
    }
    // store the event handler in the hash table
    element.events[type][handler.$$guid] = handler;
    // assign a global event handler to do all the work
    element["on" + type] = handleEvent;
  }
};
// a counter used to create unique IDs
dean_addEvent.guid = 1;

function removeEvent(element, type, handler) {
  if (element.removeEventListener) {
    element.removeEventListener(type, handler, false);
  } else {
    // delete the event handler from the hash table
    if (element.events && element.events[type]) {
      delete element.events[type][handler.$$guid];
    }
  }
};

function handleEvent(event) {
  let returnValue = true;
  // grab the event object (IE uses a global event object)
  event = event || fixEvent(((this.ownerDocument || this.document || this).parentWindow || window).event);
  // get a reference to the hash table of event handlers
  const handlers = this.events[event.type];
  // execute each event handler
  for (const i in handlers) {
    this.$$handleEvent = handlers[i];
    if (this.$$handleEvent(event) === false) {
      returnValue = false;
    }
  }
  return returnValue;
};

function fixEvent(event) {
  // add W3C standard event methods
  event.preventDefault = fixEvent.preventDefault;
  event.stopPropagation = fixEvent.stopPropagation;
  return event;
};
fixEvent.preventDefault = function() {
  this.returnValue = false;
};
fixEvent.stopPropagation = function() {
  this.cancelBubble = true;
}

// Dean's forEach: http://dean.edwards.name/base/forEach.js
/*
  forEach, version 1.0
  Copyright 2006, Dean Edwards
  License: http://www.opensource.org/licenses/mit-license.php
*/

// array-like enumeration
if (!Array.forEach) { // mozilla already supports this
  Array.forEach = function(array, block, context) {
    for (let i = 0; i < array.length; i++) {
      block.call(context, array[i], i, array);
    }
  };
}

// generic enumeration
Function.prototype.forEach = function(object, block, context) {
  for (const key in object) {
    if (typeof this.prototype[key] === "undefined") {
      block.call(context, object[key], key, object);
    }
  }
};

// character enumeration
String.forEach = function(string, block, context) {
  Array.forEach(string.split(""), function(chr, index) {
    block.call(context, chr, index, string);
  });
};

// globally resolve forEach enumeration
const forEach = function(object, block, context) {
  if (object) {
    let resolve = Object; // default
    if (object instanceof Function) {
      // functions have a "length" property
      resolve = Function;
    } else if (object.forEach instanceof Function) {
      // the object implements a custom forEach method so use that
      object.forEach(block, context);
      return;
    } else if (typeof object === "string") {
      // the object is a string
      resolve = String;
    } else if (typeof object.length === "number") {
      // the object is array-like
      resolve = Array;
    }
    resolve.forEach(object, block, context);
  }
};
