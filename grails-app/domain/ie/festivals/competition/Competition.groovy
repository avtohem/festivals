package ie.festivals.competition

class Competition {

    static Integer MIN_ANSWERS = 3

    String question
    String title
    String code
    Date end
    String description
    byte[] image

    boolean isOver() {
        end < new Date().clearTime()
    }

    void setEnd(Date endDate) {
        this.end = endDate?.clearTime()
    }

    // Use a List rather than the default Set to ensure answers are always shown in the same order
    List answers

    static hasMany = [answers: Answer]

    static constraints = {

        // Limit upload file size to 0.5MB
        Integer maxImageSize = 1024 * 1024 * 0.5
        image nullable: true, maxSize: maxImageSize

        end(validator: { end, self ->
            // only check the end date is in the future when saving for the first time
            if (!self.id && end <= new Date().clearTime()) {
                'min'
            }
        })

        title blank: false
        question blank: false
        code unique: true, matches: "[a-zA-Z0-9][a-zA-Z0-9 _-]+"
        description shared: 'unlimitedSize'

        answers minSize: MIN_ANSWERS, validator: {
            Integer correctAnswers = it.findAll { Answer answer -> answer.correct }.size()
            correctAnswers == 1
        }
    }

    static mapping = {
        description type: 'text'

        cache true
        answers cache: true, lazy: false
    }

    @Override
    String toString() {
        title
    }
}
