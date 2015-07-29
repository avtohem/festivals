<%@ page import="ie.festivals.Artist; grails.util.Environment; ie.festivals.Festival; ie.festivals.enums.FestivalType; ie.festivals.map.MapFocalPoint" %>

<html>
<head>
    <meta name="google-site-verification" content="IsdfFt1WeABuaHU7eppfGRcWVPOqP-ZooRH2krz9oGo"/>

    <meta name="description"
          content="Ireland's dedicated festivals website. Find all the key information on headline Irish festivals such as Electric Picnic and arts, comedy, sports festivals and more. We also cover festivals in the UK and Europe."/>

    <link rel="canonical" href="${grailsApplication.config.grails.serverURL}"/>

    <asset:stylesheet src="home.css"/>
</head>

<body>
<div id="fb-root"></div>

<asset:script type="text/javascript">
    $(function () {
        // initialise the artist autocompleter http://www.devbridge.com/projects/autocomplete/jquery/
        var autocompleteOptions = {
            serviceUrl: '${g.createLink(controller: "search", action: "domainClassSearch", params: [suggest: true, domainClass: Artist.simpleName])}',

            // This function causes the browser to navigate directly to an artist page when a search suggestion
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

        $('#search-artist').autocomplete(autocompleteOptions);

        // intialise the festival autocompleter
        autocompleteOptions.serviceUrl = '${g.createLink(controller: "search", action: "domainClassSearch", params: [suggest: true, domainClass: Festival.simpleName])}';
        $('#search-festival').autocomplete(autocompleteOptions);
    });

    <browser:isNotMobile>
        // Facebook Page Plugin https://developers.facebook.com/docs/plugins/page-plugin
        (function(d, s, id) {
            var js, fjs = d.getElementsByTagName(s)[0];
            if (d.getElementById(id)) return;
            js = d.createElement(s); js.id = id;
            js.src = "//connect.facebook.net/en_GB/sdk.js#xfbml=1&version=v2.4&appId=353190558223398";
            fjs.parentNode.insertBefore(js, fjs);
        }(document, 'script', 'facebook-jssdk'));
    </browser:isNotMobile>
</asset:script>

<div class="container main">

<cache:block>
    <!-- Carousel-->
    <div class="row-fluid">
        <div class="span12">
            <div id="mainCarousel" class="carousel slide">
                <div class="carousel-inner">

                    <div class="active item">
                        <festival:mapLink location="${MapFocalPoint.EUROPE}" types="${FestivalType.HEADLINE}">
                            <asset:image src="responsive/headline.jpg" alt="headline"/>

                            <div class="carousel-caption">
                                <h2>Headline Festivals in Europe</h2>

                                <p>These are the Goliaths that bestride the festival landscape, behemoths that attract the biggest international artists. Electric Picnic, Glastonbury, Exit and Sziget festival amongst others.</p>
                            </div>
                        </festival:mapLink>
                    </div>

                    <div class="item">
                        <festival:mapLink location="${MapFocalPoint.IRELAND}" types="${FestivalType.MUSIC}">
                            <asset:image src="responsive/music.jpg" alt="music"/>

                            <div class="carousel-caption">
                                <h2>Music Festivals in Ireland</h2>

                                <p>If you like music festivals but aren't so keen on big crowds, the slightly smaller music festivals are also listed here. Westport, Body and Soul and Castlepalooza are some of the festivals featured.</p>
                            </div>
                        </festival:mapLink>
                    </div>

                    <div class="item">
                        <festival:mapLink location="${MapFocalPoint.IRELAND}" types="${FestivalType.COMEDY}">
                            <asset:image src="responsive/comedy.jpg" alt="comedy"/>

                            <div class="carousel-caption">
                                <h2>Comedy Festivals in Ireland</h2>

                                <p>They say laughter is the best medicine, and we are well looked after in Ireland in terms of comedy festivals. Annual favourites include The Cat Laughs, Galway Comedy Festival and Tedfest.</p>
                            </div>
                        </festival:mapLink>
                    </div>

                    <div class="item">
                        <festival:mapLink location="${MapFocalPoint.IRELAND}" types="${FestivalType.FOOD_AND_DRINK}">

                            <asset:image src="responsive/food-and-drink.jpg" alt="food and drink"/>

                            <div class="carousel-caption">
                                <h2>Food and Drink Festivals in Ireland</h2>

                                <p>There are plenty of food and drink festivals in Ireland, including Bloom, A Taste of Dublin and A Taste of Cork.</p>
                            </div>
                        </festival:mapLink>
                    </div>
                </div>
                <a class="left carousel-control" href="#mainCarousel" data-slide="prev">&lsaquo;</a>
                <a class="right carousel-control" href="#mainCarousel" data-slide="next">&rsaquo;</a>
            </div>
        </div>
    </div>
</cache:block>

<div class="row-fluid">

    <div class="span8 spacer block-text" id="intro">
        <div class="panel">
            <div class="title clearfix">
                <h3><i class="icon-eye-open"></i> Browse Festivals by Date and Location</h3>
            </div>

            <p>
                Use the
                <g:link controller="festival" action="calendar" params="[location: MapFocalPoint.EUROPE]">calendar</g:link>
                or <festival:mapLink location="${MapFocalPoint.EUROPE}">map</festival:mapLink>
                to browse festivals by date and location.
            </p>
        </div>

        <div class="double-top-spacer panel">
            <div class="title clearfix">
                <h3><i class="icon-search"></i> Search Festivals</h3>
            </div>

            <p>Search for festivals by name or location.</p>

            <g:form method="get" class="form-search" controller="search" action="domainClassSearch" role="search">
                <div class="input-append">
                    <input type="text" name="query" class="search-query" id="search-festival" autocomplete="off"
                           placeholder="Enter Festival Name or Location"/>

                    <g:hiddenField name="domainClass" value="${Festival.simpleName}"/>
                    <button type="submit" class="btn"><i class="icon-search"></i></button>
                </div>
            </g:form>

            <div class="double-top-spacer">
                Alternatively, use the links below to browse festivals by category:
                <g:render template="/common/categoryLinks"/>
            </div>
        </div>

        <div class="double-top-spacer panel">
            <div class="title clearfix">
                <h3><i class="icon-user"></i> Find Festivals by Artist</h3>
            </div>

            <p>Find out which festivals your favourite artist will be performing at by entering their name below.</p>

            <g:form method="get" class="form-search" controller="search" action="domainClassSearch" role="search">
                <div class="input-append">
                    <input type="text" name="query" class="search-query" id="search-artist" autocomplete="off"
                           placeholder="Enter Artist Name"/>

                    <g:hiddenField name="domainClass" value="${Artist.simpleName}"/>
                    <button type="submit" class="btn"><i class="icon-search"></i></button>
                </div>
            </g:form>
        </div>
    </div>

    <!-- News & Updates-->
    <div class="span4 spacer">
        <ul class="nav nav-tabs">
            <li>
                <a href="#updates" data-toggle="tab"><i class="icon-list"></i> New Festivals</a>
            </li>
            <li class="active">
                <a href="#news" data-toggle="tab"><i class="icon-refresh"></i> Site Updates</a>
            </li>
        </ul>

        <div class="tab-content news-updates">
            <div class="tab-pane fade in" id="updates">

                <g:if test="${recentChanges || blog.countEntries()}">

                    <ul class="unstyled last">

                        <g:each in="${recentChanges.newFestivals}" status="i" var="festival">
                            <li class="${i %2 ? 'even' : 'odd'}">
                                <festival:show festival="${festival}">
                                    <i class="icon-star"></i>
                                    ${festival.name}
                                </festival:show>
                            </li>
                        </g:each>
                    </ul>
                </g:if>
            </div>

            <div class="tab-pane fade in active" id="news">
                <ul class="unstyled last">

                    <g:each in="${recentChanges.competitions}">
                        <li class="spacer">
                            <g:link controller="competition" action="show" params="[code: it.code]">
                                <i class="icon-trophy"></i>
                                <strong>New Competition:</strong> ${it.title}
                            </g:link>
                        </li>
                    </g:each>

                    <g:each in="${recentChanges.artists}">
                        <li class="spacer">
                            <artist:show id="${it.id}" name="${it.name}">
                                <i class="icon-user"></i>
                                <strong>New Artist:</strong> ${it.name}
                            </artist:show>
                        </li>
                    </g:each>

                    <g:each in="${recentChanges.lineupChanges}">
                        <li class="spacer">
                            <festival:show festival="${it}" fragment="lineup">
                                <i class="icon-user"></i>
                                <strong>Artists added to:</strong> ${it.name} lineup
                            </festival:show>
                        </li>
                    </g:each>

                    <g:each in="${recentChanges.reviews}">
                        <li class="spacer">
                            <festival:show festival="${it.festival}" fragment="review-${it.id}">
                                <i class="icon-thumbs-up"></i>
                                <strong>Review:</strong> ${it.festival.name}
                            </festival:show>
                        </li>
                    </g:each>

                    <blog:recentEntryLinks number="1">
                        <li class="last">
                            <g:link controller="blog" action="showEntry"
                                    params="[title: it.title, author: it.author]">
                                <i class="icon-pencil"></i>
                                <strong>New Blog Post:</strong> ${it.title}
                            </g:link>
                        </li>
                    </blog:recentEntryLinks>
                </ul>
            </div>
        </div>
    </div>
</div>

    <div class="row-fluid">
        <div class="span4 spacer">

            <g:if test="${favorites}">
                <g:render template="/festival/festivalTable"
                          model="[tableTitle: 'Your Favourite Festivals',
                                  tableCssClass: 'show1-3',
                                  showRemoveFavorite: true,
                                  rowIdPrefix: 'favorite',
                                  festivalInstanceList: favorites,
                                  tableId: 'favorite-festivals']"/>
            </g:if>
            <g:else>
                <g:render template="/festival/festivalTable"
                          model="[tableTitle: 'Music Festivals',
                                  tableCssClass: 'show1-3',
                                  noRowIds: true,
                                  festivalInstanceList: musicFestivals]"/>
            </g:else>
        </div>

        <!-- Upcoming Festivals-->
        <div class="span4 spacer">
            <g:render template="/festival/festivalTable"
                      model="[tableTitle: 'Upcoming Festivals',
                              tableCssClass: 'show1-3',
                              noRowIds: true,
                              festivalInstanceList: upcomingFestivals]"/>
        </div>

        <!-- Free Festivals-->
        <div class="span4 spacer" id="free">
            <g:render template="/festival/festivalTable"
                      model="[tableTitle: 'Free Festivals',
                              tableCssClass: 'show1-3',
                              noRowIds: true,
                              festivalInstanceList: freeFestivals]"/>
        </div>
    </div>
</div>

<!-- Social Media -->
<div class="container social">
    <div class="row-fluid">

        <!-- Twitter -->
        <div class="span4 spacer twitter center">
            <g:render template="/common/twitterTimeline" model="[username: 'FestivalsIrish']"/>
        </div>

        <browser:isNotMobile>
            %{-- https://developers.facebook.com/docs/plugins/page-plugin --}%
            <div class="span4 spacer facebook center">
                <div class="fb-page" data-href="https://www.facebook.com/Festivals.ie" data-width="300" data-height="350" data-small-header="false" data-adapt-container-width="true" data-hide-cover="false" data-show-facepile="true" data-show-posts="true">
                    <div class="fb-xfbml-parse-ignore">
                        <blockquote cite="https://www.facebook.com/Festivals.ie">
                            <a href="https://www.facebook.com/Festivals.ie">Festivals.ie</a>
                        </blockquote>
                    </div>
                </div>
            </div>

            <!-- Youtube -->
            <div class="span4 spacer visible-desktop">
                <g:if test="${video}">
                    <iframe width="100%" height="345px" src="${video.videoUrl}"></iframe>
                </g:if>
            </div>
        </browser:isNotMobile>
    </div>
</div>

<asset:javascript src="home.js"/>

</body>
</html>
