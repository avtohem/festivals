package ie.festivals

import grails.plugins.springsecurity.SpringSecurityService
import groovy.sql.Sql
import ie.festivals.command.FestivalGeoSearchCommand
import ie.festivals.enums.FestivalType
import ie.festivals.enums.Priority
import ie.festivals.enums.RatingType
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.hibernate.FetchMode
import grails.transaction.Transactional

@Transactional(rollbackFor = Throwable)
class FestivalService extends AbstractJdbcService {

    SpringSecurityService springSecurityService

    /**
     * If a festival is unapproved, only admins and the person who created it may view it
     * @param festival
     * @return true if the current user is allowed to view this festival
     */
    @Transactional(readOnly = true)
    boolean isAccessible(Festival festival) {
        if (SpringSecurityUtils.ifAllGranted('ROLE_ADMIN') || festival.approved) {
            return true
        }

        User festivalAuthor = festival.createdBy
        User currentUser = springSecurityService.currentUser

        // the author of a festival should always be able to view it, but we need to guard against the case where
        // both of the above are null because (null == null) => true
        currentUser && festivalAuthor && festivalAuthor.username == currentUser.username
    }

    /**
     * Delete a festival
     * @param festivalId
     * @return true/false indicating deletion succeeded/failed
     */
    boolean delete(Long festivalId) {
        Festival festival = Festival.get(festivalId)
        festival?.delete()
        festival
    }

    @Transactional(readOnly = true)
    Integer getApprovedFestivalCount() {
        Festival.createCriteria().count {
            eq 'approved', true
            cache true
        }
    }

    @Transactional(readOnly = true)
    List<Festival> favoriteFestivals() {
        User currentUser = springSecurityService.currentUser

        if (!currentUser) {
            Collections.emptyList()

        } else {
            Festival.withCriteria {
                favorites {
                    eq('user', currentUser)
                }
            }
        }
    }

    @Transactional(readOnly = true)
    List<Festival> getSimilarFestivals(Festival festival) {

        def args = [
                types: Collections.singletonList(festival.type),
                futureOnly: true,
                countryCode: festival.countryCode,
                excludeId: festival.id,
                sort: [start: 'asc']]

        def similarFestivals = findAll(args)

        // if there are no similar festivals in the same country, look for similar festivals anywhere
        similarFestivals ?: {
            args.remove('countryCode')
            findAll(args)
        }()
    }



    @Transactional(readOnly = true)
    List<Festival> getNearbyFestivals(FestivalGeoSearchCommand command) {

        // Create the RHS of an SQL list predicate, e.g. where type in ('music', 'headline')
        // these cannot be set as the value of named SQL arguments so we have to build it ourselves in a string
        // There's no risk of an SQL injection because the value was bound to a FestivalType
        List<String> festivalTypes = command.types.collect { "'${it.id}'" }
        String festivalTypesSqlList = '(' + festivalTypes.join(',') + ')'

        // To use miles instead of kilometers, replace 6371 with 3959 http://stackoverflow.com/a/574736/2648
        String query = """
                SELECT      f.*,
                            (6371 * acos(cos(radians(:lat)) * cos(radians(latitude)) * cos(radians(longitude) - radians(:lng)) + sin(radians(:lat)) * sin(radians(latitude)))) AS distance
                FROM        festival f
                WHERE       f.end >= CURDATE()
                AND         f.type in $festivalTypesSqlList
                AND         f.approved = TRUE
                HAVING      distance <= :radius
                ORDER BY    distance
                """

        def params = [
                lat: command.latitude,
                lng: command.longitude,
                radius: command.radius,
                max: command.max,
                offset: command.offset
        ]

        // Optionally add pagination params. MySQL does not allow an offset without a limit
        if (command.max) {
            query += "LIMIT :max ${command.offset ? 'OFFSET :offset' : ''}"
        }

        List<Festival> results = []
        doJdbcWork {Sql sql ->
            sql.eachRow(query, params) {row ->

                results << new Festival().with {
                    id = row.id
                    name = row.name
                    start = row.start
                    end = row.end
                    type = FestivalType.getById(row.type)
                    website = row.website

                    latitude = row.latitude
                    longitude = row.longitude
                    distance = row.distance

                    countryName = row.country_name
                    addressLine1 = row.address_line1
                    addressLine2 = row.address_line2
                    city = row.city
                    region = row.region
                    postCode = row.post_code
                    it
                }
            }
        }
        results
    }

    @Transactional(readOnly = true)
    Number getAverageRating(Festival festival, RatingType type) {

        def averageScore = Rating.createCriteria().get {
            eq('festival', festival)
            eq('type', type)

            projections {
                avg "score"
            }
            cache true
        }
        averageScore ?: 0
    }

    @Transactional(readOnly = true)
    List<Festival> getPerformances(Artist artist, boolean futureOnly = false) {

        Date today = new Date().clearTime()
        Festival.createCriteria().listDistinct {

            eq('approved', true)

            // exclude performances at past festivals
            if (futureOnly) {
                ge('end', today)
            }

            performances {
                eq('artist', artist)
                eq('deleted', false)

                // even if the festival is not over, this artist's performance(s) might be
                if (futureOnly) {
                    or {
                        isNull('date')

                        // if the performance has a date and time compare it to the current instant
                        // if the performance only has a date compare it to today
                        or {
                            and {
                                eq('hasPerformanceTime', true)
                                ge('date', new Date())
                            }

                            ge('date', today)
                        }
                    }
                }
            }

            order("start", "desc")

            cache true
        }
    }

    /**
     * Returns the next N festivals
     * @param count
     * @param freeOnly Only show free festivals
     * @return
     */
    @Transactional(readOnly = true)
    List<Festival> nextFestivals(Integer count, boolean freeOnly = false, boolean hasVideoOnly = false,
                                 List<FestivalType> types = Collections.emptyList()) {
        Festival.withCriteria {
            ge('end', new Date().clearTime())
            eq('approved', true)

            if (freeOnly) {
                eq('freeEntry', true)
            }

            if (hasVideoOnly) {
                isNotNull('videoUrl')
            }

            if (types) {
                'in'('type', types)
            }
            order("start", "asc")
            maxResults(count)

            cache true
        }
    }

    @Transactional(readOnly = true)
    List<Review> latestReviews(Integer count) {
        Review.withCriteria {

            order("dateCreated", "desc")
            maxResults(count)

            cache true
        }
    }

    @Transactional(readOnly = true)
    List<Festival> recentlyAddedFestivals(Integer count) {
        Festival.withCriteria {
            ge('end', new Date().clearTime())
            eq('approved', true)
            order("dateCreated", "desc")
            maxResults(count)

            cache true
        }
    }

    /**
     * List festivals by recently changed lineup
     * @param max number of results to return
     * @return
     */
    @Transactional(readOnly = true)
    List<Festival> listFestivalsByPerformanceAdded(Integer count) {

        Festival.executeQuery('''
                select distinct f, p.dateCreated  
                from Festival as f
                inner join f.performances as p
                where p.dateCreated is not null
                order by p.dateCreated desc''', [max: count])
    }

    @Transactional(readOnly = true)
    Festival getVideoFestival() {
        List<Festival> nextFestivalWithVideo = nextFestivals(1, false, true, [FestivalType.HEADLINE])
        nextFestivalWithVideo ? nextFestivalWithVideo[0] : getRandomFestivalVideo()
    }

    private Festival getRandomFestivalVideo() {

        def festivalVideos = Festival.withCriteria {
            isNotNull('videoUrl')
            eq('approved', true)
            cache true
        }

        // Randomly choose one of the videos
        if (festivalVideos) {
            Collections.shuffle(festivalVideos)
            festivalVideos.first()
        }
    }

    /**
     * Saves a rating for a festival and returns the new average rating
     * @param festival
     * @param user
     * @param score
     */
    Number addRating(Festival festival, User user, RatingType type, Number score) {

        // Make sure each user can only rate each festival once
        Rating rating = getRating(festival, user, type)

        if (!rating) {
            new Rating(festival: festival, user: user, type: type, score: score).save(failOnError: true)
        }
        getAverageRating(festival, type)
    }

    @Transactional(readOnly = true)
    Rating getRating(Festival festival, User user, RatingType type) {
        Rating.findWhere(user: user, festival: festival, type: type)
    }

    /**
     * Retrieve festivals matching various criteria
     * @param params All of the following parameters are optional:
     *
     * <ul>
     *     <li>types - If unspecified, all types will be matched. If an empty collection is provided nothing will be matched</li>
     *     <li>dateRange - Only festivals occurring within this time period will be returned. If this parameter is provided <tt>futureOnly</tt> will be ignored</li>
     *     <li>futureOnly - If true, festivals in the past will be ignored</li>
     *     <li>freeOnly - If true, only festivals that don't charge an admission fee will be included</li>
     *     <li>countryCode - If not null, only festivals in this country will be returned</li>
     *     <li>excludeId - If provided, exclude the festival with this ID</li>
     *     <li>max - maximum number of results to return</li>
     *     <li>offset - offset for the results</li>
     *     <li>sort - an optional Map that defines the sort order, e.g. <tt>[name: 'desc']</tt></li>
     * </ul>
     * @return
     */
    @Transactional(readOnly = true)
    List<Festival> findAll(Map params) {

        Collection<FestivalType> types = params.types != null ? params.types : FestivalType.values()
        ObjectRange dateRange = params.dateRange
        boolean futureOnly = params.futureOnly
        String countryCode = params.countryCode
        Long excludeFestivalId = params.excludeId

        if (types.isEmpty()) {
            return Collections.emptyList()
        }

        def festivals = Festival.withCriteria {
            'in'('type', types)
            eq('approved', true)
            if (excludeFestivalId) {
                ne('id', excludeFestivalId)
            }

            if (dateRange) {
                def startDate = dateRange.from
                def endDate = dateRange.to

                or {
                    between("start", startDate, endDate)
                    between("end", startDate, endDate)
                }
            } else if (futureOnly) {
                ge('end', new Date().clearTime())
            }

            if (params.freeOnly) {
                eq('freeEntry', true)
            }

            if (countryCode) {
                eq('countryCode', countryCode)
            }

            if (params.hasLineup != null) {
                eq('hasLineup', params.hasLineup)
            }

            if (params.max) {
                maxResults(params.max)
                firstResult(params.offset)
            }

            if (params.sort) {
                Map.Entry<String, String> sortSpec = params.sort.iterator().next()
                order(sortSpec.key, sortSpec.value)
            }
            cache true
        }

        log.debug "${festivals.size()} match query $params "
        festivals
    }

    @Transactional(readOnly = true)
    List<Performance> getLineup(Festival festival) {
        Performance.withCriteria {
            eq('festival', festival)
            eq('deleted', false)
            order("priority", "asc")

            // eagerly load the artists
            fetchMode("artist", FetchMode.JOIN)
            cache true
        }
    }

    @Transactional(readOnly = true)
    Map<Priority, List<Performance>> getPrioritisedLineup(Festival festival) {

        List<Performance> performances = getLineup(festival)
        performances.groupBy {it.priority}
    }
}
