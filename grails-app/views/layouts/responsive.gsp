<%@ page import="ie.festivals.enums.FestivalType; ie.festivals.Artist; ie.festivals.map.MapFocalPoint; ie.festivals.Festival" %>
<!DOCTYPE html>
<!--[if lt IE 7 ]> <html lang="en" class="no-js ie6"> <![endif]-->
<!--[if IE 7 ]>    <html lang="en" class="no-js ie7"> <![endif]-->
<!--[if IE 8 ]>    <html lang="en" class="no-js ie8"> <![endif]-->
<!--[if IE 9 ]>    <html lang="en" class="no-js ie9"> <![endif]-->
<!--[if (gt IE 9)|!(IE)]><!--> <html lang="en" class="no-js"><!--<![endif]-->

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>

    <!-- Mobile Specific Metas
	==================================================  -->
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <g:set var="title" value="Festivals in Ireland, UK and Europe | Festivals.ie"/>
    <title><g:layoutTitle default="${title}"/></title>

    %{--og:title and og:description are used when posting links to Facebook using either the Like button or the --}%
    %{--Facebook button in the addThis plugin--}%
    <meta property="og:title" content="${g.layoutTitle(default: title)}"/>
    <meta property="og:description" content="${pageProperty(name: 'meta.description') ?:
        'Ireland&#39;s dedicated festivals website. Find all the key information on headline Irish festivals such as Electric Picnic and arts, comedy, sports festivals and more. If you are planning a trip overseas we also cover festivals in the UK and Europe.'}"/>

    %{--More OpenGraph properties that Facebook uses. See these links for details:--}%
    %{--http://developers.facebook.com/docs/reference/plugins/like/ http://developers.facebook.com/tools/debug--}%
    %{--This image will be used when a page is shared via the AddThis plugin--}%
    <meta property="og:image" content="${assetPath(src: 'banners/love-festivals-299-250.gif', absolute: true)}"/>

    <meta property="og:type" content="website"/>

    %{--This is the ID for Donal's personal Facebook account. I can't find an equivalent for Festivals.ie--}%
    <meta property="fb:admins" content="565111843"/>

    <asset:link rel="shortcut icon" href="favicon.ico" type="image/x-icon"/>

    <link href='http://fonts.googleapis.com/css?family=Open+Sans:400italic,700italic,400,700,300' rel='stylesheet'
          type='text/css'>
    <link href='http://fonts.googleapis.com/css?family=Kreon' rel='stylesheet' type='text/css'>

    <!--[if lt IE 9]>
    <script type="text/javascript" src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script>
    <![endif]-->

    <asset:stylesheet src="default.css"/>
    <asset:javascript src="head.js"/>
    <g:layoutHead/>
</head>

<body>
<div class="wrapper">

    <!-- Fixed Nav -->
    <div class="navbar navbar-fixed-top top-nav">
        <div class="navbar-inner">
            <div class="container">
                <ul class="nav login-register">
                    <li>
                        <g:link uri='/'>
                            <i class="icon-home icon"></i><span>Home</span>
                        </g:link>
                    </li>

                    <sec:ifLoggedIn>
                        <li><g:link controller="logout">Logout</g:link></li>
                    </sec:ifLoggedIn>

                    <sec:ifNotLoggedIn>
                        <li><a data-toggle="modal" href="#login-modal">Login</a></li>
                        <li><a data-toggle="modal" href="#register-modal">Register</a></li>
                    </sec:ifNotLoggedIn>
                    <sec:ifAllGranted roles="ROLE_ADMIN">
                        <li><g:link controller="admin">Admin</g:link></li>
                    </sec:ifAllGranted>

                    <li id="search-toggle" class="hide">
                        <a href="javascript:void(0)" title="Toggle Search">
                            <i class="icon-search icon"></i>
                        </a>
                    </li>
                </ul>
                <g:form method="get" class="form-search pull-right" name="searchform" action="search" controller="search" role="search">
                    <div class="input-append">
                        <input type="text" name="query" value="${params.query}" class="search-all search-query input-large"
                               placeholder="Find Artist or Festival" autocomplete="off"/>
                        <button type="submit" class="btn"><i class="icon-search"></i></button>
                    </div>
                </g:form>
                <ul class="pull-right hidden-phone social-links">
                    <li>
                        <a target="_blank" href="https://www.facebook.com/Festivals.ie" title="Visit Festivals.ie on Facebook">
                            <i class="icomoon facebook-icon">&#xe001;</i>
                        </a>
                    </li>
                    <li>
                        <a target="_blank" href="https://twitter.com/FestivalsIrish" title="Visit Festivals.ie on Twitter">
                            <i class="icomoon twitter-icon">&#xe000;</i>
                        </a>
                    </li>
                    <li>
                        <a target="_blank" href="http://www.youtube.com/user/FestivalsIrish" title="Visit Festivals.ie on YouTube">
                            <i class="icomoon youtube-icon">&#xe002;</i>
                        </a>
                    </li>
                </ul>


            </div>
            <ul class="center visible-phone social-links" id="mobile-map-links">

                <g:each in="${FestivalType.values()}" var="type">
                    <li title="Show ${type.toString().toLowerCase()} festivals on map">
                        <festival:mapLink types="${type}">
                            <asset:image src="map/${type.id}.png"/>
                        </festival:mapLink>
                    </li>
                </g:each>
            </ul>
        </div>
    </div>

    <!-- Login Modal -->
    <div id="login-modal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="login-modal-label"
         aria-hidden="true">
        <div class="modal-header">
            <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>

            <h2 id="login-modal-label">Login</h2>
        </div>

        <div class="modal-body">

            <div class="modal-left-col block">
                <h3 class="first">Festivals.ie Login</h3>

                <form class="last no-control-group" action="${request.contextPath}/j_spring_security_check" method="post">
                    <label for="j_username">Email</label>
                    <g:textField name="j_username" class="block" maxlength="191"/>

                    <label for="j_password">Password</label>
                    <g:passwordField name="j_password" class="block"/>

                    <label class="checkbox">
                        <input type="checkbox" class="valign" name="_spring_security_remember_me" checked="checked"/> Remember me
                    </label>

                    <button type="submit" class="btn">Login</button>

                    <ul class="double-top-spacer">
                        <li>Forgot password?
                            <a href="${createLink(controller: 'register', action: 'beginPasswordReset')}">Recover it here</a>
                        </li>
                        <li>Need an account? <g:link controller="register" action="newUser">Sign up here</g:link></li>
                    </ul>

                </form>
            </div>

            <div class="modal-right-col block">
                <h3 class="first">Social Login</h3>

                <p>You can also use any of these services to login to Festivals.ie.</p>
                <g:render template="/login/socialLinks"/>

                <p>If your account was created using a social service, you must use this same service to login.</p>
            </div>
        </div>
    </div>

    <!-- Register Modal -->
    <div id="register-modal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="register-modal-label"
         aria-hidden="true">
        <div class="modal-header">
            <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>

            <h2 id="register-modal-label">Register</h2>
        </div>

        <div class="modal-body">

            <div class="modal-left-col block">
                <h3 class="first">Festivals.ie Registration</h3>
                <g:form class="last no-control-group" controller="register" action="register">
                    <label for="username">Email</label>
                    <g:textField name="username" class="block" maxlength="191"/>

                    <label for="name">Name</label>
                    <g:textField name="name" class="block" maxlength="191"/>

                    <label for="password">Password</label>
                    <g:passwordField name="password" class="block"/>

                    <label>Confirm Password</label>
                    <g:passwordField name="passwordConfirm" class="block"/>

                    <label class="checkbox">
                        I accept the <g:link target="_blank" uri="/terms">Terms &amp; Conditions</g:link>
                        <input type='checkbox' name='terms' id='terms' class="valign"
                            ${'terms' in params ? "checked='checked'" : ''}/>
                    </label>

                    <img src="${createLink(controller: 'simpleCaptcha', action: 'captcha')}" alt="CAPTCHA"/>
                    <label for="captcha">Type the letters above in the box below</label>
                    <g:textField name="captcha"/>

                    <button type="submit" class="btn">Register</button>
                </g:form>
            </div>

            <div class="modal-right-col block">
                <h3 class="first">Social Registration</h3>

                <p>If you have an account with any of the services below, you can use it to register with Festivals.ie.</p>
                <g:render template="/login/socialLinks"/>

                <h3 class="double-top-spacer">Login</h3>
                <p>If you already have an account, <g:link controller="login">click here to login</g:link> instead.</p>
            </div>

            <div class="modal-full-width" id="why-register-container">
                <h3>Why Register?</h3>

                <g:render template="/login/whyRegister"/>
            </div>
        </div>
    </div>

    <!-- Header -->
    <div class="container header">
        <div class="logo">
            <g:link uri='/'>
                <asset:image src="logo/festivals.svg" alt="Logo" class="pull-left"
                       data-png-fallback="${assetPath(src: 'logo/festivals.png')}"/>
            </g:link>
    
            <div class="pull-right hidden-phone number-badge dark-bg" id="festivals-listed">
                <div class="top">
                    <div class="like-h1">
                        <festival:mapLink location="${MapFocalPoint.EUROPE}" title="Show all festivals">
                        %{--added to the model by FestivalFilters--}%
                            ${approvedFestivalCount}
                        </festival:mapLink>
                    </div>
                </div>
    
                <div class="bottom">
                    <festival:mapLink location="${MapFocalPoint.EUROPE}" title="Show all festivals">
                        <div class="like-h2">Festivals Listed!</div>
                    </festival:mapLink>
                </div>
            </div>
        </div>
    </div>

    <!-- Main Nav-->
    <div class="container">
        <div class="row-fluid">
            <div class="span12">
                <div class="navbar main-nav">
                    <div class="navbar-inner">
                        <a class="btn btn-navbar collapsed" data-toggle="collapse" data-target=".nav-collapse">Menu <b
                                class="caret"></b></a>

                        <div class="nav-collapse">
                            <ul class="nav">
                                <li class="dropdown">
                                    <a id="drop1" href="javascript:void(0)" role="button" class="dropdown-toggle"
                                       data-toggle="dropdown">Irish Festivals<b class="caret"></b></a>
                                    <ul class="dropdown-menu" role="menu" aria-labelledby="drop1">
                                        <li role="menuitem">
                                            <festival:mapLink tabindex="-1"
                                                              location="${MapFocalPoint.IRELAND}">Map</festival:mapLink>
                                        </li>
                                        <li role="menuitem">
                                            <g:link tabindex="-1" controller="festival" action="calendar"
                                                    params="[location: MapFocalPoint.IRELAND]">
                                                Calendar
                                            </g:link>
                                        </li>
                                        <li role="menuitem">
                                            <festival:listLink tabindex="-1"
                                                               location="${MapFocalPoint.IRELAND}">List</festival:listLink>
                                        </li>
                                    </ul>
                                </li>
                                <li class="dropdown">
                                    <a id="drop2" href="javascript:void(0)" role="button" class="dropdown-toggle"
                                       data-toggle="dropdown">UK Festivals<b class="caret"></b></a>
                                    <ul class="dropdown-menu" role="menu" aria-labelledby="drop2">
                                        <li role="menuitem">
                                            <festival:mapLink tabindex="-1"
                                                              location="${MapFocalPoint.UK}">Map</festival:mapLink>
                                        </li>
                                        <li role="menuitem">
                                            <g:link tabindex="-1" controller="festival" action="calendar"
                                                    params="[location: MapFocalPoint.UK]">
                                                Calendar
                                            </g:link>
                                        </li>
                                        <li role="menuitem">
                                            <festival:listLink tabindex="-1"
                                                               location="${MapFocalPoint.UK}">List</festival:listLink>
                                        </li>
                                    </ul>
                                </li>
                                <li class="dropdown">
                                    <a id="drop3" href="javascript:void(0)" role="button" class="dropdown-toggle"
                                       data-toggle="dropdown">European Festivals<b class="caret"></b></a>
                                    <ul class="dropdown-menu" role="menu" aria-labelledby="drop3">
                                        <li role="menuitem">
                                            <festival:mapLink tabindex="-1"
                                                              location="${MapFocalPoint.EUROPE}">Map</festival:mapLink>
                                        </li>
                                        <li role="menuitem">
                                            <g:link tabindex="-1" controller="festival" action="calendar"
                                                    params="[location: MapFocalPoint.EUROPE]">
                                                Calendar
                                            </g:link>
                                        </li>
                                        <li role="menuitem">
                                            <festival:listLink tabindex="-1"
                                                               location="${MapFocalPoint.EUROPE}">List</festival:listLink>
                                        </li>
                                    </ul>
                                </li>
                                <li class="dropdown small">
                                    <a id="drop4" href="javascript:void(0)" role="button" class="dropdown-toggle"
                                       data-toggle="dropdown">Alerts<b class="caret"></b></a>
                                    <ul class="dropdown-menu" role="menu" aria-labelledby="drop4">
                                        <li role="menuitem">
                                            <g:link tabindex="-1" controller='artistSubscription' action='list'>Artist</g:link>
                                        </li>
                                        <li role="menuitem">
                                            <g:link tabindex="-1" controller='festivalSubscription' action='list'>Festival</g:link>
                                        </li>
                                    </ul>
                                </li>
                                <li class="small">
                                    <g:link controller='artist' action='list' params="[name: 'A']">Artists</g:link>
                                </li>
                                <li class="small">
                                    <g:link controller='festival' action='create' class="no-wrap">Add Festival</g:link>
                                </li>
                                <li class="small">
                                    <g:link controller="blog" action="list">Blog</g:link>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    %{--include page-specific content--}%
    <g:layoutBody/>

    <!-- Footer -->
    <div class="navbar footer">
        <div class="navbar-inner">
            <div class="container">
                <ul class="nav pull-left">
                    <li>
                        <a href="javascript:void(0)" id="to-top" title="Return to the top of this page">
                            <i class="icon-circle-arrow-up"></i>Back to Top
                        </a>
                    </li>
                    <li><g:link uri="/about">About Us</g:link></li>
                    <li>
                        <g:link controller="home" action="contact">Contact Us</g:link>
                    </li>
                    <li><g:link uri="/terms">Terms &amp; Conditions</g:link></li>
                    <li><g:link uri="/privacy">Privacy Policy</g:link></li>
                    <li><g:link uri="/writeForUs">Write For Us</g:link></li>
                    <li><g:link uri="/apiDocs">Developer API</g:link></li>
                </ul>
            </div>
        </div>
    </div>

    %{--Show flash messages in the top message bar--}%
    <g:render template="/common/notificationBar"/>

    %{--dialog that is shown when AJAX request is in progress--}%
    <div id="spinner" style="display:none;" class="shadow">
        <asset:image src="spinner.gif" alt="Loading..."/>
    </div>

    <div class="push"></div>
</div>

<div class="footer-image"></div>

<asset:script>
    $(document).ready(function () {
            // initialise the autocompleter http://www.devbridge.com/projects/autocomplete/jquery/
            var autocompleteOptions = {
                serviceUrl: '${g.createLink(controller: "search", action: "suggest")}',

            // This function causes the browser to navigate directly to an artist/festival page when a search suggestion
            // is shown. Remove this function if we just want to show the search results for the suggestion instead.
            onSelect: function(suggestion) {

                document.location.href = suggestion.data.url;
            },

            // Strikethrough the name of festivals that are over
            formatResult: function (suggestion, currentValue) {
                var resultText = suggestion.value;
                return suggestion.data.finished ? '<span class="finished">' + resultText + '</span>' : resultText;
            }
        };

        $('input.search-all').autocomplete(autocompleteOptions);
    });
</asset:script>

<asset:javascript src="main.js"/>
<asset:deferredScripts/>

</body>
</html>