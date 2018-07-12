document.addEventListener('DOMContentLoaded', function() {
    var elems = document.querySelectorAll('.tap-target');
    
    if
    	{
    		var instances = M.TapTarget.init(elems, onClose);
 	 instance.open();
 	}

 	else{
 		   instance.close();
 	}


	 var instance = M.TapTarget.getInstance(elems);
  
  
  	instance.destroy();

  });