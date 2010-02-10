


HMIPv6 RFC: 
-----------
[TXT][1]
[PDF][2]


Details:
--------

Uses C++ types but no real class usage. 

The strategy I have taken to implementing HMIPv6 is to implement the MAP
and HMIPv6 MN as simple process models which can be attached to the IP 
stack of any existing Node Models. 

MAP Operations:

*	Receive BU's, add to bind cache and send a BAck. 
*	Intercept packets addressed to RCoA and tunnel them to the LCoA.

Mobile Node Operations:

*	Setup LCoA and RCoA
*	Send BU to MAP with both addresses
*	Receive Back.
*	Interact with nodes outside MAP through tunnel with MAP.

AP Operations:

* Send out advertisements of MAP.

Project ToDo Items:

<table>
  <tr>
    <th>ID</th><th>Task</th><th>Status</th>
  </tr>
  <tr>
    <td>1</td>
    <td>Setup MAP Advertisements from AP</td>
    <td>Done</td>
  </tr>
  <tr>
    <td>2</td>
    <td>Write MAP Advert processing in Mobile Node</td>
    <td>Done</td>
  </tr>
  <tr>
    <td>3</td>
    <td>Setup RCoA Generation from Map Address in Mobile Node</td>
    <td>Done</td>
  </tr>
  <tr>
    <td>4</td>
    <td>Debug Simulation</td>
    <td>Working</td>
  </tr
</table>


[1]: http://www.ietf.org/rfc/rfc4140.txt "RFC 4140"
[2]: http://www.faqs.org/ftp/rfc/pdf/rfc4140.txt.pdf "RFC 4141 PDF

