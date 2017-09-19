namespace UsersAPI
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("REGISTER")]
    public partial class REGISTER
    {
        [Required]
        [StringLength(50)]
        public string firstName { get; set; }

        [Required]
        [StringLength(50)]
        public string lastName { get; set; }

        [Key]
        [StringLength(100)]
        public string emailId { get; set; }

        [Required]
        [StringLength(30)]
        public string password { get; set; }

        public long? phoneNo { get; set; }

        [StringLength(300)]
        public string residence { get; set; }

        public DateTime dateOfBirth { get; set; }

        [Required]
        [StringLength(6)]
        public string gender { get; set; }

        public virtual SECURITY_QUESTIONS SECURITY_QUESTIONS { get; set; }
    }
}
