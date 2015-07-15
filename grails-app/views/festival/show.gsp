<%@ page import="ie.festivals.enums.*" %>

<head>
    <title><content:title>${festival.name}</content:title></title>
    <meta name="description" content="${description}"/>

    <asset:stylesheet href="festival.css"/>

    <g:set var="ratingImgDir" value="${assetPath(src: 'raty')}"/>
    <g:set var="showMap" value="${festival.latitude && festival.longitude}"/>

    <sec:ifLoggedIn>
        <asset:stylesheet href="wysihtml5/custom.css"/>
    </sec:ifLoggedIn>

    <link rel="canonical" href="${canonicalUrl}"/>
</head>

<body>
<g:set var="df" value="${grailsApplication.config.festival.dateFormat}"/>

<!-- Main Content-->
<div class="container main" itemscope itemtype="http://schema.org/Festival">

    <meta itemprop="startDate" content="${festival.start.format(df)}"/>
    <meta itemprop="endDate" content="${festival.end.format(df)}"/>

    <!-- Festival Title-->
    <div class="title clearfix">
        <h1 class="pull-left" itemprop='name'>${festival.name.encodeAsHTML()}</h1>
        <div class="pull-right title-btn-wrapper" id="title-btn-group">
            <div class="btn-group pull-left" data-toggle="buttons-checkbox">

                %{--If the festival is unapproved and a non-admin user is viewing it, they must be creator.
                Provide an edit button that will allow them to make further changes--}%
                <g:if test="${!festival.approved}">
                    <sec:ifNotGranted roles='ROLE_ADMIN'>
                        <g:link class="btn" id="${festival.id}" action="edit">
                            <i class="icon-edit"></i> Edit Festival
                        </g:link>
                    </sec:ifNotGranted>
                </g:if>

                <g:render template="/common/festivalSubscribeButton"/>
                <g:render template="favoriteFestivalButton"/>
            </div>
        </div>
    </div>

    %{-- the Skiddle ticket button may have been added to a festival that wasn't imported from Skiddle #774 --}%
    <g:set var="hasSkiddleUrl" value="${!festival.source == FestivalSource.SKIDDLE && festival.skiddleUrl}"/>

    <div class="row-fluid">

        <!-- Festival Details-->
        <div class="span8 spacer">
            <div class="tab-wrapper">
                <ul class="nav nav-tabs">
                    <li class="active"><a href="#overview" data-toggle="tab">Overview</a></li>

                    <g:if test="${festival.synopsis}">
                        <li><a href="#synopsis" data-toggle="tab">Synopsis</a></li>
                    </g:if>

                    <g:if test="${festival.ticketInfo || hasSkiddleUrl}">
                        <li><a href="#tickets" data-toggle="tab">Tickets</a></li>
                    </g:if>

                    <li><a href="#gettingThere" data-toggle="tab">Getting There</a></li>
                    <li><a href="#accomodation" data-toggle="tab">Accommodation</a></li>
                    <li><a href="#ratings" data-toggle="tab">Ratings</a></li>
                </ul>

                <div class="tab-content">
                    <div class="tab-pane active" id="overview">
                        <table class="table table-bordered table-striped smaller last">
                            <tbody>
                            <tr>
                                <td>Countdown</td>
                                <td>
                                    <g:if test="${countdown == null}">
                                        This festival is over
                                    </g:if>
                                    <g:elseif test="${countdown == 0}">
                                        This festival is happening today
                                    </g:elseif>
                                    <g:elseif test="${countdown == 1}">
                                        This festival starts tomorrow
                                    </g:elseif>
                                    <g:else>
                                        ${countdown} days until this festival starts
                                    </g:else>
                                </td>
                            </tr>
                            <g:if test="${reminderRange && festival.approved}">
                                <tr>
                                    <td>Reminder</td>
                                    <sec:ifLoggedIn>
                                        <td id="reminder">
                                            <g:render template="reminder"/>
                                        </td>
                                    </sec:ifLoggedIn>
                                    <sec:ifNotLoggedIn>
                                        <td>If you wish to receive a reminder about this festival, you must <g:link controller="login">login</g:link> first.</td>
                                    </sec:ifNotLoggedIn>
                                </tr>
                            </g:if>
                            <tr>
                                <g:set var="overviewDateFormat" value="EEE, MMM d yyyy"/>
                                <g:if test="${festival.multiDayDuration}">
                                    <td>Dates</td>
                                    <td>
                                        <g:formatDate format="${overviewDateFormat}" date="${festival.start}"/> —
                                        <g:formatDate format="${overviewDateFormat}" date="${festival.end}"/>
                                    </td>
                                </g:if>
                                <g:else>
                                    <td>Date</td>
                                    <td><g:formatDate format="${overviewDateFormat}" date="${festival.start}"/></td>
                                </g:else>
                            </tr>
                            <tr>
                                <td>Address</td>
                                <td>${festival.getFullAddress(true).encodeAsHTML()}</td>
                            </tr>
                            <tr>
                                <td>Country</td>
                                <td>${festival.countryName.encodeAsHTML()}</td>
                            </tr>
                            <tr>
                                <td>Type</td>
                                <td>${festival.type}</td>
                            </tr>

                            <g:if test="${festival.website}">
                                <tr>
                                    <td>Website</td>
                                    <td><a target="_blank" rel="nofollow" href="${festival.website}">${festival.website.size() > 50 ? 'Visit Festival Website' : festival.website}</a></td>
                                </tr>
                            </g:if>

                            <tr>
                                <td>Free Admission</td>
                                <td>${festival.freeEntry ? 'Yes' : 'No'}</td>
                            </tr>

                            <g:if test="${festival.earlyBirdExpiry >= new Date().clearTime()}">
                                <tr>
                                    <td>Early Bird Expiry</td>
                                    <td>
                                        Tickets are available at a discount price if purchased before <g:formatDate date="${festival.earlyBirdExpiry}"/>
                                    </td>
                                </tr>
                            </g:if>

                            <g:if test="${festival.previousOccurrence}">
                                <tr>
                                    <td>Previous Occurrence</td>
                                    <td>This festival was <g:link action="show" id="${festival.previousOccurrence.id}">last held</g:link>
                                        on <g:formatDate date="${festival.previousOccurrence.start}"/></td>
                                </tr>
                            </g:if>

                            </tbody>
                        </table>
                    </div>

                <span itemprop="location" itemscope itemtype="http://schema.org/Place">

                    <span itemprop="geo" itemscope itemtype="http://schema.org/GeoCoordinates">
                        <meta itemprop="latitude" content="${festival.latitude}" />
                        <meta itemprop="longitude" content="${festival.longitude}" />
                    </span>
                </span>

                <g:if test="${festival.synopsis}">
                    <div class="tab-pane" id="synopsis" itemprop="description">
                        ${festival.synopsis}
                    </div>
                </g:if>

                <g:if test="${festival.ticketInfo || hasSkiddleUrl}">
                    <div class="tab-pane" id="tickets">

                        <g:if test="${festival.ticketInfo}">
                            ${festival.ticketInfo}
                        </g:if>

                        %{-- the Skiddle ticket button may have been added to a festival that wasn't imported from Skiddle #774 --}%
                        <g:if test="${hasSkiddleUrl}">
                            <g:render template="buyTicketsButton" model="[ticketUrl: festival.skiddleUrl]"/>
                        </g:if>
                    </div>
                </g:if>

                    <div class="tab-pane" id="gettingThere">
                        <h4>Driving Directions</h4>

                        <p>For driving directions to the festival, enter the address or place name you will be departing from in the box below (directions to the festival will be displayed in a new browser window/tab).</p>

                        <form id="directions" class="no-control-group">
                            <label for="depart">Departing From</label>
                            <input id="depart" type="text" class="block" placeholder="Departure address or place name"/>
                            <button type="submit" class="btn btn-small"><i class="icon-search"></i> Get Directions</button>
                        </form>

                        <g:if test="${festival.countryCode == 'irl' && !festival.finished}">

                            <h4>Public Transport &amp; Car Sharing</h4>
                            <p>For information about how to reach the festival by public transport or to request a lift, enter the town/city and day of departure below (public transport and car sharing options will be displayed in a new browser window/tab).</p>

                            <g:set var="defaultTravelDate" value="${new Date().after(festival.start) ? new Date() : festival.start}"/>

                            <form id="public-transport" class="no-control-group">
                                <label for="travel-date">Travel Date</label>
                                <input type="text" class="datepicker" data-date-format="yyyy-mm-dd"
                                       placeholder="Day of departure" readonly="readonly" id="travel-date"
                                       value="${defaultTravelDate.format(df)}"/>

                                <label for="origin">Departing From</label>
                                <input type="text" placeholder="Town or city of departure" class="block" id="origin"/>
                                <button type="submit" class="btn btn-small"><i class="icon-search"></i> Search</button>
                            </form>

                            <cache:render template="getThereLinks" key="${festival.id}"/>
                        </g:if>
                    </div>

                    <div class="tab-pane clearfix" id="accomodation">
                        <h4 class="pull-left spacer">Search hotels on
                            <a href="http://www.booking.com/index.html?aid=348662" target="_blank">
                                <asset:image src="booking.com.gif" alt="booking.com"/>
                            </a>
                        </h4>

                        <g:set var="affiliateId" value="${grailsApplication.config.festivals.bookingDotComAffiliateId}"/>

                        <form class="clear last no-control-group" action="http://www.booking.com/searchresults.html" id="booking">

                            %{--Docs for these fields: https://admin.bookings.org/affiliate/impl_sbox.html--}%
                            <input type="hidden" name="aid" value="${affiliateId}"/>
                            <input type="hidden" name="error_url" value="http://www.booking.com/?aid=${affiliateId};"/>
                            <input type="hidden" name="si" value="ai,co,ci,re,di"/>
                            <input type="hidden" name="label" value=""/>
                            <input type="hidden" name="lang" value="en-gb"/>
                            <input type="hidden" name="ifl" value="1"/>

                            <label for="ss">Destination</label>
                            <g:set var="bookingDotComAddress" value='${festival.city ? "${festival.city}, ${festival.countryName}" : ""}'/>
                            <g:textField name="ss" class="block" placeholder="Enter Festival Town / City" value="${bookingDotComAddress}"/>

                            <label for="checkin">Check-in date</label>
                            <g:textField name="checkin" class="datepicker input-medium" data-date-format="yyyy-mm-dd"
                                         readonly="readonly" value="${accomStart?.format(df)}"/>

                            <label for="checkout">Check-out date</label>
                            <g:textField name="checkout" class="datepicker input-medium" data-date-format="yyyy-mm-dd"
                                         readonly="readonly" value="${accomEnd?.format(df)}"/>

                            <label class="checkbox">
                                <input type="checkbox" name="idf" style="margin: 3px 5px 0 0;"/>I don't have specific dates yet
                            </label>
                            <button type="submit" class="btn"><i class="icon-search"></i> Search</button>
                        </form>
                    </div>

                    <div class="tab-pane" id="ratings">
                        <h4>Rate this Festival</h4>

                        <sec:ifNotLoggedIn>
                            <div class="spacer alert">You must <g:link controller="login">login</g:link> to rate festivals.</div>
                        </sec:ifNotLoggedIn>

                        <sec:ifLoggedIn>
                            <g:if test="${ticketRateable || lineupRateable}">
                                <div class="alert alert-block fade in spacer">
                                    <button type="button" class="close" data-dismiss="alert">×</button>

                                    <p><strong>Heads Up!</strong> You can only rate each festival once, so if you're planning to
                                        attend this festival please consider waiting until after the event before rating!
                                    </p>
                                </div>

                                <table class="table table-bordered table-striped">
                                    <tbody>
                                        <g:if test="${ticketRateable}">
                                            <tr>
                                                <td>Ticket Price</td>
                                                <td><span id="ticketRating" class="rating"></span></td>
                                            </tr>
                                        </g:if>

                                        <g:if test="${lineupRateable}">
                                            <tr>
                                                <td>Lineup</td>
                                                <td><span id="lineupRating" class="rating"></span></td>
                                            </tr>
                                        </g:if>
                                    </tbody>
                                </table>
                            </g:if>
                            <g:else>
                                <div class="spacer alert">You have already rated this festival.</div>
                            </g:else>
                        </sec:ifLoggedIn>

                        <h4>Average Ratings for this Festival</h4>
                        <table class="table table-bordered table-striped last">
                            <tbody>
                                <tr>
                                    <td>Ticket Price</td>
                                    <td><span id="ticketAverage" class="rating"></span></td>
                                </tr>
                                <tr>
                                    <td>Lineup</td>
                                    <td><span id="lineupAverage" class="rating"></span></td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

         %{-- Festival Location --}%
        <div class="span4 spacer center">
            <g:if test="${showMap}">
                %{--The marker scale param is undocumented, but it makes the scale of the marker match the scale of the map. Without--}%
                %{--this, the marker image was horribly pixelated. The marker scale param only works if we use the default marker image size--}%
                %{--http://stackoverflow.com/a/17130379/2648--}%
                <img src="http://maps.googleapis.com/maps/api/staticmap?size=145x160&amp;scale=2&amp;zoom=${mapData.zoom - 1}&amp;markers=scale:2|${mapData.center.latitude},${mapData.center.longitude}"/>
            </g:if>

            <div class="social-links double-top-spacer">
                <cache:render template="/common/addThis"/>
            </div>
        </div>
    </div>

    <sec:ifAllGranted roles='ROLE_ADMIN'>
        <div class="row-fluid">

            <div class="span12 lineup panel spacer" style="padding-bottom: 0;">
                <div class="title clearfix">
                    <h3>Admin</h3>

                    <div class="title-btn-wrapper">
                        <span class="pull-left">
                            <g:if test="${festival.source == FestivalSource.HUMAN}">
                                Festival added by
                                <g:if test="${festival.createdBy}">
                                    <a href="mailto:${festival.createdBy.username}">${festival.createdBy.name}</a>
                                </g:if>
                                <g:else>
                                    an unknown user
                                </g:else>
                            </g:if>
                            <g:else>
                                Festival imported from ${festival.source}
                            </g:else>
                            at <g:formatDate date="${festival.dateCreated}" formatName="default.time.format"/>
                        </span>

                        <div class="btn-group pull-right" style="margin-top: 0;">
                            <g:link class="btn" id="${festival.id}" action="edit">
                                <i class="icon-edit"></i> Edit Festival
                            </g:link>

                            <g:link class="btn" id="${festival.id}" action="createClone">
                                <i class="icon-repeat"></i> Clone Festival
                            </g:link>

                            %{--use a form here, because a POST should be sent--}%
                            <g:form action="delete" id="${festival.id}" name="delete-festival"
                                    onsubmit="return confirm('${g.message(code: 'festival.delete.confirm')}');">

                                <input style="height: 32px" class="btn btn-danger last" id="${festival.id}"
                                       type="submit" value="Delete Festival"/>
                            </g:form>
                        </div>
                    </div>
                </div>

                <g:if test="${festival.hasLineup}">
                    <div id="add-performer-panel">
                        <h4>Add Performance</h4>
                        <g:render template="/artist/searchForm" model="[searchController: 'performance', searchAction: 'performerSearch', festivalId: festival.id]"/>
                    </div>
                </g:if>
                <g:else>
                    <div class="spacer alert double-top-spacer">
                        A lineup is not currently permitted for this festival. Use the Has Lineup field in the
                        <g:link action="edit" id="${festival.id}">edit festival form</g:link> to change this setting.
                    </div>
                </g:else>
            </div>
        </div>
    </sec:ifAllGranted>

    <g:set var="hasPerformers" value="${prioritisedLineup.values().any()}"/>
    <g:set var="showLineup" value="${hasPerformers || festival.lineupUrl}"/>

    <div class="row-fluid" id="bottomArtistList" style="${showLineup ? '' : 'display: none'}">

        <!-- Lineup -->
        <div class="span12 lineup">
            <div class="title clearfix">
                <h2 class="pull-left" style="display: inline; margin-right: 10px;">Lineup</h2>
            </div>

            <g:set var="multiplePriorities" value="${prioritisedLineup[Priority.HEADLINE] && prioritisedLineup[Priority.MIDLINE]}"/>
            <g:set var="multipleDates" value="${filterDates?.size() > 1}"/>

            <div id="artistsNotEmpty" style="${hasPerformers ? '' : 'display: none'}">

                <g:if test="${multiplePriorities || multipleDates}">
                    <div class="spacer" id="lineup-filter">

                        %{--only show the lineup radio buttons if there are artists of different priorities--}%
                        <g:if test="${multiplePriorities}">
                            <h4>Filter Lineup by Artist</h4>
                            <label class="lineup-toggle">
                                <input type="radio" name="lineup" checked="checked" id="all-artists"/>Show All Artists
                            </label>
                            <label class="lineup-toggle">
                                <input type="radio" name="lineup" id="headline-artists-only"/>Show Headline Artists Only
                            </label>
                        </g:if>

                        <g:if test="${multipleDates}">
                            <h4>Filter Lineup by Date</h4>
                            <g:each in="${filterDates}" var="festivalDay">
                                <span class="date-option">
                                    <g:set var="checkBoxName" value="${css.getDateClass(date: festivalDay)}"/>

                                    <label for="${checkBoxName}">
                                        <g:formatDate date="${festivalDay}" format="E d MMM" />
                                        <g:checkBox class="festival-date-filter" name="${checkBoxName}" value="${true}"/>
                                    </label>
                                </span>
                            </g:each>
                        </g:if>
                    </div>
                </g:if>
                <p>
                    A selection of the artists appearing at ${festival.name.encodeAsHTML()} is shown below. Click on the artists to see their bio page.
                    <g:if test="${festival.lineupUrl}">
                        The latest information about the lineup for ${festival.name.encodeAsHTML()} is <a href="${festival.lineupUrl}" target="_blank">available here</a>.
                    </g:if>
                </p>
            </div>

            <g:if test="${festival.lineupUrl}">
                <div id="artistsEmpty" style="${hasPerformers ? 'display: none' : ''}">
                    <p>The latest information about the lineup for ${festival.name.encodeAsHTML()} is <a href="${festival.lineupUrl}" target="_blank">available here</a>.</p>
                </div>
            </g:if>

            <div class="artistsList">
                <g:each in="${prioritisedLineup}">
                    <g:set var="priority" value="${it.key}"/>
                    <g:set var="performances" value="${it.value}"/>

                    <div id="${priority.id}">
                        <g:each in="${performances}">
                            <g:render template="/artist/artistListEntry"
                                    model="${[artist: it.artist,
                                            performance: it,
                                            performer: true,
                                            artistAction: ArtistAction.LINEUP_DELETE]}"/>
                        </g:each>
                    </div>
                </g:each>
            </div>
        </div>
    </div>

    <div class="row-fluid">
        <g:if test="${festival.videoUrl}">
            %{--make the video wider if there is no twitter feed or similar festivals--}%
            <g:set var="wideVideo" value="${!festival.twitterUsername || !similarFestivals}"/>

            <div class="${wideVideo ? 'span8' : 'span4'} spacer">
                <iframe width="100%" height="345px" src="${festival.videoUrl}"></iframe>
            </div>
        </g:if>

        <g:if test="${festival.twitterUsername}">
            <div class="span4 spacer twitter center">
                <g:render template="/common/twitterTimeline" model="[username: festival.twitterUsername]"/>
            </div>
        </g:if>

        <g:if test="${similarFestivals}">
            <div class="span4 spacer">
                <div id="similarCarousel" class="carousel slide last">
                    <div class="carousel-caption dark-bg top">
                        <h3>Similar Festivals</h3>
                    </div>

                    <div class="carousel-inner">

                        <g:each in="${similarFestivals}" status="i" var="similar">

                            <div class="${i == 0 ? 'active' : ''} item text-only">
                                <h3><festival:show festival="${similar}"/></h3>

                                <g:if test="${similar.multiDayDuration}">
                                    <p><g:formatDate date="${similar.start}"/> — <g:formatDate date="${similar.end}"/></p>
                                </g:if>
                                <g:else>
                                    <p><g:formatDate date="${similar.start}"/></p>
                                </g:else>

                                <p class="last">${similar.city.encodeAsHTML()}, ${similar.countryName.encodeAsHTML()}</p>
                            </div>
                        </g:each>
                    </div>

                    <g:if test="${similarFestivals.size() > 1}">
                        <a class="left carousel-control" href="#similarCarousel" data-slide="prev">&lsaquo;</a>
                        <a class="right carousel-control" href="#similarCarousel" data-slide="next">&rsaquo;</a>
                    </g:if>

                    <div class="carousel-caption dark-bg">
                        <h3>
                            <g:link action="showSimilarFestivals" id="${festival.id}">Show All</g:link>
                        </h3>
                    </div>
                </div>
            </div>
        </g:if>
    </div>

    <div class="row-fluid">

        <g:set var="reviewCount" value="${approvedReviews.size()}"/>

        <!-- Reviews -->
        <g:if test="${approvedReviews}">

            <div class="span6 spacer">
                <div class="title clearfix">

                    <h2 class="pull-left">
                        <g:if test="${reviewCount == 1}">1 Festival Review</g:if>
                        <g:else>${reviewCount} Festival Reviews</g:else>
                    </h2>
                </div>

                <div class="well last">
                    <div id="reviewsCarousel" class="carousel slide last">
                        <div class="carousel-inner spacer">

                            <g:each in="${approvedReviews}" var="review" status="i">
                                <div class="item ${i == 0 ? 'active' : ''}" id="review-${review.id}">
                                    <h3 class="first">${review.title.encodeAsHTML()}</h3>
                                    <p>${review.body}</p>

                                    <p class="muted last">
                                        <small>
                                            <strong>${review.author.name.encodeAsHTML()}</strong> |
                                            <g:formatDate date="${review.dateCreated}"/>
                                        </small>
                                    </p>
                                </div>
                            </g:each>
                        </div>

                        <g:if test="${reviewCount > 1}">
                            <a class="btn prevReview" href="#reviewsCarousel" data-slide="prev">
                                <i class="icon-circle-arrow-left"></i> Previous
                            </a>

                            <span class="badge">Review <span class="reviewIndex">1</span> of
                                <span class="reviewCount">${reviewCount}</span>
                            </span>

                            <a class="btn last nextReview" href="#reviewsCarousel" data-slide="next">Next
                                <i class="icon-circle-arrow-right"></i>
                            </a>
                        </g:if>
                    </div>
                </div>
            </div>
        </g:if>

        <!-- Leave a Review -->
        <div class="span6 spacer">
            <div class="title clearfix">
                <h2 class="pull-left">Submit a Review</h2>
            </div>

            <sec:ifLoggedIn>
                <g:form class="review last" controller="review" action="submit">
                    <g:hiddenField name="festival.id" value="${festival.id}"/>

                    <f:field bean="review" property="title"/>
                    <f:field bean="review" property="body" label="Review">
                        <g:textArea name="${property}" value="${value}" rows="6" cols="1" class="block rich"/>
                    </f:field>

                    <button type="submit" class="btn"><i class="icon-comment"></i> Submit</button>
                </g:form>
            </sec:ifLoggedIn>
            <sec:ifNotLoggedIn>
                <div>
                    <p class="alert">
                        You must <g:link controller="register" action="newUser">register</g:link> or
                        <g:link controller="login" action="auth">login</g:link> before you can submit a review.
                    </p>
                    <p>Reviews will be published on the site once they have been approved by a moderator.</p>
                </div>
            </sec:ifNotLoggedIn>
        </div>
    </div>
</div>

<asset:script>
    $(document).ready(function () {

        // handler for the driving directions form
        var endAddress = '${festival.fullAddress.encodeAsURL()}';

        $('#directions').submit(function() {
            var startAddress = $('#depart').val();
            startAddress = $.trim(startAddress);

            if (startAddress.length > 0) {
                startAddress = encodeURIComponent(startAddress);
                var googleMapsUrl = 'http://maps.google.com/maps?saddr=' + startAddress + '&daddr=' + endAddress + '&hl=en';
                window.open(googleMapsUrl);
            }
            return false;
        });

        // handler for the public transport form
        var destination = '${festival.city}';
        var monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

        $('#public-transport').submit(function() {
            var origin = $.trim($('#origin').val());
            var travelDate = $.trim($('#travel-date').val());

            if (origin.length > 0 && travelDate.length > 0) {

                travelDate = SF.parseDate(travelDate);
                var getThereDate = travelDate.getDate() + '-' + monthNames[travelDate.getMonth()] + '-' + travelDate.getFullYear();
                var getThereUrl = 'http://getthere.ie/' + encodeURIComponent(origin) + '-' + encodeURIComponent(destination) + '/' + getThereDate;
                window.open(getThereUrl);
            }
            return false;
        });

        // Setup the star ratings
        var ratingHints = ['very poor', 'poor', 'fair', 'good', 'very good'];

        var showRating = function(selector, ratingType, averageSelector) {
            $(selector).raty({
                score: 0,
                path: '${ratingImgDir}',
                hints: ratingHints,
                click: function(score, evt) {

                    var ratingControl = $(this);

                    $.ajax({
                        url: '${createLink(action: 'addRating')}',
                        type: 'POST',
                        data: {score: score, festivalId: ${festival.id}, type: ratingType},
                        success: function(data) {

                            // Disable the rating control
                            ratingControl.raty('readOnly', true);

                            // Update the average rating
                            $(averageSelector).raty('readOnly', false).raty('score', data.updatedAverage).raty('readOnly', true);

                            $().notificationMsg({
                                    message: 'Thanks for rating! The average has been updated to include your rating',
                                    cssClass: 'MessageBarCommon MessageBarOk'
                            });
                        }
                    })
                }
            });
        };

        // Initialise the rating controls
        <g:if test="${ticketRateable}">
            showRating('#ticketRating', '${RatingType.TICKET_PRICE.name()}', '#ticketAverage');
        </g:if>

        <g:if test="${lineupRateable}">
            showRating('#lineupRating', '${RatingType.LINEUP.name()}', '#lineupAverage');
        </g:if>

        // Initialise the average rating controls
        $('#ticketAverage').raty({
            score: ${ticketRating},
            noRatedMsg: 'Ticket prices have not been rated yet',
            path: '${ratingImgDir}',
            hints: ratingHints,
            half: true,
            readOnly: true
        });

        $('#lineupAverage').raty({
            score: ${lineupRating},
            noRatedMsg: 'Lineup has not been rated yet',
            path: '${ratingImgDir}',
            hints: ratingHints,
            half: true,
            readOnly: true
        });

        // Make a separate Isotope container for each lineup priority
        SF.container = {};

        // Make a JS array out of the priorities
        var priorityNames = ${Priority.values().collect {"'" + it.id + "'"}};

        for (var i = 0; i < priorityNames.length; i++) {

            var priorityName = priorityNames[i];
            var containerId = '#' + priorityName;

            // Create the container and store it in globally accessible scope
            SF.container[priorityName] = SF.layoutImageContent(containerId, containerId + ' .artistEntry', 'perfDate');
        }
    });
</asset:script>

<sec:ifLoggedIn>
    <asset:javascript src="wysihtml5/init.js"/>
</sec:ifLoggedIn>

<asset:javascript src="festival.js"/>
</body>
