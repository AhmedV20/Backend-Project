using AutoMapper;
using DotnetAuth.Domain.Contracts;
using DotnetAuth.Domain.Entities;
using System;

namespace DotnetAuth.Infrastructure.Mapping
{
    public class GenderTypeConverter : ITypeConverter<string, Gender>
    {
        public Gender Convert(string source, Gender destination, ResolutionContext context)
        {
            if (string.IsNullOrEmpty(source)) return Gender.Male;
            return Enum.TryParse<Gender>(source, true, out var result) ? result : Gender.Male;
        }
    }

    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<ApplicationUser, UserResponse>()
                .ForMember(dest => dest.FullName, opt => opt.MapFrom(src => src.FullName))
                .ForMember(dest => dest.Gender, opt => opt.MapFrom(src => src.Gender.ToString()));
            
            CreateMap<ApplicationUser, CurrentUserResponse>()
                .ForMember(dest => dest.FullName, opt => opt.MapFrom(src => src.FullName))
                .ForMember(dest => dest.Gender, opt => opt.MapFrom(src => src.Gender.ToString()));
            
            CreateMap<UserRegisterRequest, ApplicationUser>()
                .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email))
                .ForMember(dest => dest.FirstName, opt => opt.MapFrom(src => src.FirstName))
                .ForMember(dest => dest.LastName, opt => opt.MapFrom(src => src.LastName))
                .ForMember(dest => dest.Gender, opt => opt.MapFrom(src => src.Gender))
                .ForMember(dest => dest.UserName, opt => opt.Ignore())
                .ForMember(dest => dest.Role, opt => opt.Ignore())
                .ForMember(dest => dest.CreateAt, opt => opt.Ignore())
                .ForMember(dest => dest.UpdateAt, opt => opt.Ignore())
                .ForMember(dest => dest.IsEmailConfirmed, opt => opt.Ignore())
                .ForMember(dest => dest.EmailConfirmed, opt => opt.Ignore());

            CreateMap<string, Gender>().ConvertUsing<GenderTypeConverter>();
            CreateMap<Gender, string>().ConvertUsing(gender => gender.ToString());
        }
    }
}
